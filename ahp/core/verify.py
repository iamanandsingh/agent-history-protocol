"""Chain verification — Section 5.4 of the AHP specification."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Optional

from ahp.core.chain import ChainReader, parse_envelope, parse_gap_payload
from ahp.core.types import SCHEMA_VERSION, ZERO_HASH_32, RecordType


@dataclass
class VerifyResult:
    valid: bool
    records_checked: int
    gaps: int
    broken_at: Optional[int] = None
    expected_hash: Optional[bytes] = None
    actual_hash: Optional[bytes] = None
    error: Optional[str] = None


def verify_chain(path: str, *, allow_nonzero_start: bool = False) -> VerifyResult:
    """Verify hash chain integrity per Section 5.4.

    Uses streaming iteration (iter_records) to avoid loading the entire
    chain into memory at once.

    Checks:
    1. First record's prev_hash == 32 zero bytes
    2. Each subsequent record's prev_hash == SHA-256(stored_bytes of previous)
    3. Sequence numbers are monotonic with no gaps (except GapRecords)
    4. GapRecord constraints (first_lost_sequence, last_lost_sequence, count)

    Args:
        path: Path to the chain file.
        allow_nonzero_start: When True, skip the genesis zero-hash check and
            the seq=1 requirement for the first record.  Set this when
            verifying a *rotated segment* file whose first record continues
            from a previous segment (i.e. prev_hash is the hash of the last
            record in the prior segment and the sequence does not start at 1).
    """
    reader = ChainReader(path)

    expected_seq = 1
    gaps = 0
    prev_stored = None
    records_checked = 0

    for i, stored in enumerate(reader.iter_records()):
        try:
            envelope = parse_envelope(stored)
        except (ValueError, KeyError) as exc:
            return VerifyResult(
                valid=False,
                records_checked=i + 1,
                gaps=gaps,
                broken_at=i + 1,
                error=f"Malformed record at index {i}: {exc}",
            )
        seq = envelope["sequence"]
        prev_hash = envelope["prev_hash"]
        record_type_val = envelope["record_type"]

        # Validate schema version
        if envelope["schema_version"] != SCHEMA_VERSION:
            return VerifyResult(
                valid=False,
                records_checked=i + 1,
                gaps=gaps,
                broken_at=seq,
                error=f"Unsupported schema version {envelope['schema_version']} at sequence {seq} (expected {SCHEMA_VERSION})",
            )

        # Validate enum value
        try:
            record_type = RecordType(record_type_val)
        except ValueError:
            return VerifyResult(
                valid=False,
                records_checked=i + 1,
                gaps=gaps,
                broken_at=seq,
                error=f"Invalid record_type {record_type_val} at sequence {seq}",
            )

        # Check hash chain
        if i == 0:
            if allow_nonzero_start:
                # Rotated segment: accept any prev_hash and any starting sequence.
                expected_seq = seq
            elif not hmac.compare_digest(prev_hash, ZERO_HASH_32):
                return VerifyResult(
                    valid=False,
                    records_checked=i + 1,
                    gaps=gaps,
                    broken_at=seq,
                    error="Genesis record prev_hash is not zero bytes",
                )
        else:
            if prev_stored is None:  # should never happen when i > 0
                raise RuntimeError(f"prev_stored is None at record index {i}, sequence {seq}")
            expected_hash = hashlib.sha256(prev_stored).digest()
            if not hmac.compare_digest(prev_hash, expected_hash):
                return VerifyResult(
                    valid=False,
                    records_checked=i + 1,
                    gaps=gaps,
                    broken_at=seq,
                    expected_hash=expected_hash,
                    actual_hash=prev_hash,
                    error=f"Hash chain broken at record #{seq} (sequence {seq}). "
                    f"Record #{seq - 1 if seq > 1 else 0} may have been modified.",
                )

        # Check sequence
        if record_type == RecordType.GAP:
            if seq <= expected_seq:
                return VerifyResult(
                    valid=False,
                    records_checked=i + 1,
                    gaps=gaps,
                    broken_at=seq,
                    error=f"GapRecord sequence {seq} is not greater than expected {expected_seq}",
                )

            # Validate GapRecord payload constraints (Section 3.3)
            gap_data = parse_gap_payload(envelope["payload_bytes"])
            gap_first = gap_data["first_lost_sequence"]
            gap_last = gap_data["last_lost_sequence"]
            gap_count = gap_data["count"]

            if gap_first != expected_seq:
                return VerifyResult(
                    valid=False,
                    records_checked=i + 1,
                    gaps=gaps,
                    broken_at=seq,
                    error=f"GapRecord first_lost_sequence {gap_first} != expected {expected_seq}",
                )
            if gap_last != seq - 1:
                return VerifyResult(
                    valid=False,
                    records_checked=i + 1,
                    gaps=gaps,
                    broken_at=seq,
                    error=f"GapRecord last_lost_sequence {gap_last} != sequence - 1 ({seq - 1})",
                )
            if gap_count != gap_last - gap_first + 1:
                return VerifyResult(
                    valid=False,
                    records_checked=i + 1,
                    gaps=gaps,
                    broken_at=seq,
                    error=f"GapRecord count {gap_count} != last - first + 1 ({gap_last - gap_first + 1})",
                )

            gaps += 1
        else:
            if seq != expected_seq:
                return VerifyResult(
                    valid=False,
                    records_checked=i + 1,
                    gaps=gaps,
                    broken_at=seq,
                    error=f"Expected sequence {expected_seq}, got {seq}",
                )

        expected_seq = seq + 1
        prev_stored = stored
        records_checked = i + 1

    return VerifyResult(
        valid=True,
        records_checked=records_checked,
        gaps=gaps,
    )
