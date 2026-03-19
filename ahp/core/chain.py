"""Chain file writer and reader.

Chain file format (Appendix C):
  Header: 4B magic "AHP\0" + 4B version + 8B creation timestamp
  Records: [4B length][NB canonical_bytes][4B CRC32C] repeated
"""

from __future__ import annotations

import hashlib
import os
import struct
import threading
import time
import zlib
from pathlib import Path
from typing import IO, Optional, Union

from ahp.core.canonical import canonical_bytes
from ahp.core.records import (
    PAYLOAD_TYPE_MAP,
    CheckpointPayload,
    GapPayload,
    Payload,
    Record,
    RecoveryPayload,
)
from ahp.core.types import SCHEMA_VERSION, ZERO_HASH_32, GapReason, RecordType, RecoveryMethod
from ahp.core.uuid7 import uuid7
from ahp.core.validation import MAX_RECORD_SIZE, validate_record

# File format constants
MAGIC = b"AHP\x00"
FILE_VERSION = 1
HEADER_SIZE = 16  # 4 + 4 + 8


class ChainWriter:
    """Writes records to a chain file with hash chain integrity."""

    def __init__(
        self,
        path: Union[str, Path],
        agent_id: Optional[bytes] = None,
        session_id: Optional[bytes] = None,
        fsync_mode: str = "batch",
        fsync_batch_size: int = 1000,
        prev_hash: Optional[bytes] = None,
        start_sequence: int = 0,
    ):
        self.path = Path(path)
        self.agent_id = agent_id or uuid7()
        self.session_id = session_id or uuid7()
        self._sequence = start_sequence
        self._prev_hash = prev_hash if prev_hash is not None else ZERO_HASH_32
        self._record_count = 0
        self._gap_count = 0
        self._fsync_mode = fsync_mode  # "every", "batch", "none"
        self._fsync_batch_size = fsync_batch_size
        self._writes_since_fsync = 0
        self._lock = threading.Lock()

        self._lock_file: Optional[IO[str]] = None
        self._data_file: Optional[IO[bytes]] = None  # must be set before _acquire_file_lock (for safe __del__)
        self._lock_path = str(self.path) + ".lock"
        self._acquire_file_lock()

        if not self.path.exists():
            self._write_header()

        # Initialize in-memory byte counter (eliminates stat() per record for rotation check)
        self._bytes_written = self.path.stat().st_size

        # Open persistent handle for appending
        self._data_file = open(self.path, "ab")

    def _acquire_file_lock(self) -> None:
        """Acquire exclusive file lock to prevent multi-process corruption."""
        self._lock_file = open(self._lock_path, "w")
        try:
            import fcntl

            fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except ImportError:
            # fcntl not available (Windows) — fall back to msvcrt.locking()
            try:
                import msvcrt

                # Write a byte so the file has content to lock, then seek back
                self._lock_file.write("\x00")
                self._lock_file.flush()
                self._lock_file.seek(0)
                msvcrt.locking(self._lock_file.fileno(), msvcrt.LK_NBLCK, 1)  # type: ignore[attr-defined]
            except ImportError:
                pass  # Neither fcntl nor msvcrt — skip locking
            except (IOError, OSError):
                self._lock_file.close()
                self._lock_file = None
                raise RuntimeError(
                    f"Chain file '{self.path}' is locked by another process. "
                    f"Only one ChainWriter per chain file is allowed."
                )
        except (IOError, OSError):
            self._lock_file.close()
            self._lock_file = None
            raise RuntimeError(
                f"Chain file '{self.path}' is locked by another process. "
                f"Only one ChainWriter per chain file is allowed."
            )

    def close(self) -> None:
        """Release persistent file handle, file lock, and clean up."""
        # Close persistent data file handle
        if self._data_file is not None:
            try:
                self._data_file.flush()
                self._data_file.close()
            except OSError:
                pass
            self._data_file = None

        if self._lock_file:
            try:
                import fcntl

                fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_UN)
            except ImportError:
                # Windows: release the msvcrt byte-range lock
                try:
                    import msvcrt

                    self._lock_file.seek(0)
                    msvcrt.locking(self._lock_file.fileno(), msvcrt.LK_UNLCK, 1)  # type: ignore[attr-defined]
                except (ImportError, OSError):
                    pass
            except OSError:
                pass
            try:
                self._lock_file.close()
            except OSError:
                pass
            # Clean up .lock file
            try:
                os.unlink(self._lock_path)
            except OSError:
                pass
            self._lock_file = None

    def __del__(self):
        self.close()

    def _write_header(self) -> None:
        with open(self.path, "wb") as f:
            f.write(MAGIC)
            f.write(struct.pack("<I", FILE_VERSION))
            f.write(struct.pack("<Q", int(time.time() * 1000)))

    def write_record(
        self, payload: Payload, session_id: Optional[bytes] = None, timestamp_ms: Optional[int] = None
    ) -> Record:
        """Create a record, compute hash chain, write to file. Returns the record."""
        with self._lock:
            return self._write_record_unlocked(payload, session_id, timestamp_ms)

    def write_gap(self, first_lost: int, last_lost: int, reason: GapReason, detail: str = "") -> Record:
        """Write a GapRecord documenting lost records.

        The GapRecord's sequence = last_lost + 1 (per spec Section 3.3).
        Updates internal sequence counter to match.
        """
        count = last_lost - first_lost + 1
        # Override sequence: gap record's sequence = last_lost + 1
        # The lock inside write_record will be acquired there; adjust _sequence
        # before calling write_record. We need to hold the lock for the whole
        # operation to keep it atomic.
        with self._lock:
            self._sequence = last_lost  # will be incremented to last_lost + 1 by _write_record_unlocked
            payload = GapPayload(
                first_lost_sequence=first_lost,
                last_lost_sequence=last_lost,
                count=count,
                reason=reason,
                detail=detail,
            )
            return self._write_record_unlocked(payload)

    def write_recovery(
        self,
        records_verified: int,
        records_truncated: int,
        last_valid_seq: int,
        method: RecoveryMethod = RecoveryMethod.CHAIN_SCAN,
        detail: str = "",
    ) -> Record:
        """Write a RecoveryRecord after crash recovery."""
        payload = RecoveryPayload(
            records_verified=records_verified,
            records_truncated=records_truncated,
            last_valid_seq=last_valid_seq,
            recovery_method=method,
            detail=detail,
        )
        return self.write_record(payload)

    def write_checkpoint(self) -> Record:
        """Write a BatchCheckpoint summarizing current chain state."""
        with self._lock:
            payload = CheckpointPayload(
                record_count=self._record_count + 1,  # including this checkpoint
                gap_count=self._gap_count,
                chain_hash=self._prev_hash,
            )
            return self._write_record_unlocked(payload)

    def _write_record_unlocked(
        self, payload: Payload, session_id: Optional[bytes] = None, timestamp_ms: Optional[int] = None
    ) -> Record:
        """Internal write_record without acquiring the lock (caller must hold it)."""
        self._sequence += 1

        record = Record(
            record_id=uuid7(),
            agent_id=self.agent_id,
            session_id=session_id or self.session_id,
            timestamp_ms=timestamp_ms or int(time.time() * 1000),
            sequence=self._sequence,
            prev_hash=self._prev_hash,
            schema_version=SCHEMA_VERSION,
            record_type=PAYLOAD_TYPE_MAP[type(payload)],
            payload=payload,
        )

        # Validate record before serialization (fail-open: emit GapRecord on error)
        # Skip validation for replacement GapRecords to prevent infinite recursion
        is_gap_replacement = isinstance(payload, GapPayload) and payload.detail.startswith("Validation failed:")
        errors = [] if is_gap_replacement else validate_record(record)
        if errors:
            import logging

            _logger = logging.getLogger("ahp.chain")
            _logger.warning("Record validation failed (emitting GapRecord): %s", errors)
            # Replace with a GapRecord instead of crashing
            gap_payload = GapPayload(
                first_lost_sequence=self._sequence,
                last_lost_sequence=self._sequence,
                count=1,
                reason=GapReason.INTERCEPTOR_FAILURE,
                detail="Validation failed: " + "; ".join(errors),
            )
            record = Record(
                record_id=record.record_id,
                agent_id=self.agent_id,
                session_id=session_id or self.session_id,
                timestamp_ms=record.timestamp_ms,
                sequence=self._sequence,
                prev_hash=self._prev_hash,
                schema_version=SCHEMA_VERSION,
                record_type=RecordType.GAP,
                payload=gap_payload,
            )

        # Serialize to canonical bytes
        stored = canonical_bytes(record)
        record._stored_bytes = stored

        # Save old state for rollback on I/O failure
        old_prev_hash = self._prev_hash
        old_sequence = self._sequence
        old_record_count = self._record_count
        old_gap_count = self._gap_count
        old_bytes_written = self._bytes_written

        # Update chain state
        self._prev_hash = hashlib.sha256(stored).digest()
        self._record_count += 1
        if record.record_type == RecordType.GAP:
            self._gap_count += 1

        # Write to file: [length][canonical_bytes][crc32c]
        # Uses persistent file handle to reduce open/close syscall overhead
        try:
            f = self._data_file
            if f is None or f.closed:
                # Reopen if handle was lost (shouldn't happen in normal flow)
                self._data_file = open(self.path, "ab")
                f = self._data_file

            length = len(stored)
            length_bytes = struct.pack("<I", length)
            crc = struct.pack("<I", zlib.crc32(length_bytes + stored) & 0xFFFFFFFF)
            frame = length_bytes + stored + crc
            f.write(frame)
            f.flush()
            self._bytes_written += len(frame)

            # fsync per spec Section 10.1
            self._writes_since_fsync += 1
            if self._fsync_mode == "every":
                os.fsync(f.fileno())
                self._writes_since_fsync = 0
            elif self._fsync_mode == "batch" and self._writes_since_fsync >= self._fsync_batch_size:
                os.fsync(f.fileno())
                self._writes_since_fsync = 0
            # "none" — no fsync, OS decides
        except OSError:
            # Rollback in-memory state so the chain stays consistent
            self._prev_hash = old_prev_hash
            self._sequence = old_sequence
            self._record_count = old_record_count
            self._gap_count = old_gap_count
            self._bytes_written = old_bytes_written
            raise

        return record

    @property
    def sequence(self) -> int:
        return self._sequence

    @property
    def prev_hash(self) -> bytes:
        return self._prev_hash

    @property
    def record_count(self) -> int:
        return self._record_count

    @property
    def gap_count(self) -> int:
        return self._gap_count

    @property
    def bytes_written(self) -> int:
        return self._bytes_written


class ChainReader:
    """Reads records from a chain file."""

    def __init__(self, path: Union[str, Path]):
        self.path = Path(path)

    def iter_records(self):
        """Yield stored_bytes one at a time. Never loads all into memory."""
        if not self.path.exists():
            return
        with open(self.path, "rb") as f:
            header = f.read(HEADER_SIZE)
            if len(header) < HEADER_SIZE or header[:4] != MAGIC:
                return
            while True:
                length_bytes = f.read(4)
                if len(length_bytes) < 4:
                    break
                length = struct.unpack("<I", length_bytes)[0]
                if length > MAX_RECORD_SIZE:
                    raise ValueError(f"Record length {length} exceeds maximum of 1MB")
                stored = f.read(length)
                if len(stored) < length:
                    break
                crc_bytes = f.read(4)
                if len(crc_bytes) < 4:
                    break
                expected_crc = struct.unpack("<I", crc_bytes)[0]
                actual_crc = zlib.crc32(length_bytes + stored) & 0xFFFFFFFF
                if actual_crc != expected_crc:
                    break
                yield stored

    def read_all(self) -> list:
        """Read all stored_bytes from the chain file."""
        return list(self.iter_records())

    def read_range(self, start_seq: int, end_seq: int) -> list:
        """Read records in a sequence range without loading entire chain."""
        results = []
        for stored in self.iter_records():
            env = parse_envelope(stored)
            seq = env["sequence"]
            if start_seq <= seq <= end_seq:
                results.append(stored)
            if seq > end_seq:
                break
        return results

    def count(self) -> int:
        """Count records without loading all into memory."""
        return sum(1 for _ in self.iter_records())


def parse_envelope(stored_bytes: bytes) -> dict:
    """Parse the common envelope from canonical bytes.

    Returns dict with: record_id, agent_id, session_id, timestamp_ms,
    sequence, prev_hash, schema_version, record_type, payload_bytes.
    """
    if len(stored_bytes) < 104:  # minimum envelope size
        raise ValueError("Record too short for envelope")

    offset = 0
    record_id = stored_bytes[offset : offset + 16]
    offset += 16
    agent_id = stored_bytes[offset : offset + 16]
    offset += 16
    session_id = stored_bytes[offset : offset + 16]
    offset += 16
    timestamp_ms = struct.unpack("<Q", stored_bytes[offset : offset + 8])[0]
    offset += 8
    sequence = struct.unpack("<Q", stored_bytes[offset : offset + 8])[0]
    offset += 8
    prev_hash = stored_bytes[offset : offset + 32]
    offset += 32
    schema_version = struct.unpack("<I", stored_bytes[offset : offset + 4])[0]
    offset += 4
    record_type_val = struct.unpack("<I", stored_bytes[offset : offset + 4])[0]
    offset += 4

    # Skip payload type discriminator (same as record_type)
    _payload_type = struct.unpack("<I", stored_bytes[offset : offset + 4])[0]
    offset += 4

    return {
        "record_id": record_id,
        "agent_id": agent_id,
        "session_id": session_id,
        "timestamp_ms": timestamp_ms,
        "sequence": sequence,
        "prev_hash": prev_hash,
        "schema_version": schema_version,
        "record_type": RecordType(record_type_val),
        "payload_offset": offset,
        "payload_bytes": stored_bytes[offset:],
        "stored_bytes": stored_bytes,
    }


def parse_action_payload(payload_bytes: bytes) -> dict:
    """Parse ActionPayload fields from canonical bytes after the envelope."""
    offset = 0
    parent_action_id = payload_bytes[offset : offset + 16]
    offset += 16

    tool_name, offset = _read_string(payload_bytes, offset)
    parameters_hash = payload_bytes[offset : offset + 16]
    offset += 16
    result_hash = payload_bytes[offset : offset + 16]
    offset += 16
    result_status = struct.unpack("<I", payload_bytes[offset : offset + 4])[0]
    offset += 4
    response_time_ms = struct.unpack("<I", payload_bytes[offset : offset + 4])[0]
    offset += 4
    protocol = struct.unpack("<I", payload_bytes[offset : offset + 4])[0]
    offset += 4
    action_type = struct.unpack("<I", payload_bytes[offset : offset + 4])[0]
    offset += 4
    target_entity, offset = _read_string(payload_bytes, offset)
    evidence_uri, offset = _read_string(payload_bytes, offset)
    redacted = payload_bytes[offset] == 0x01
    offset += 1
    model_id, offset = _read_string(payload_bytes, offset)
    input_token_count = struct.unpack("<I", payload_bytes[offset : offset + 4])[0]
    offset += 4
    output_token_count = struct.unpack("<I", payload_bytes[offset : offset + 4])[0]
    offset += 4

    # Authorization (nested)
    auth_type = struct.unpack("<I", payload_bytes[offset : offset + 4])[0]
    offset += 4
    entry_count = struct.unpack("<I", payload_bytes[offset : offset + 4])[0]
    offset += 4

    auth_entries = []
    for _ in range(entry_count):
        authorizer_type = struct.unpack("<I", payload_bytes[offset : offset + 4])[0]
        offset += 4
        authorizer_id, offset = _read_string(payload_bytes, offset)
        authorizer_agent_id = payload_bytes[offset : offset + 16]
        offset += 16
        authorizer_seq = struct.unpack("<Q", payload_bytes[offset : offset + 8])[0]
        offset += 8
        decision = struct.unpack("<I", payload_bytes[offset : offset + 4])[0]
        offset += 4
        condition, offset = _read_string(payload_bytes, offset)
        auth_timestamp = struct.unpack("<Q", payload_bytes[offset : offset + 8])[0]
        offset += 8
        auth_entries.append(
            {
                "authorizer_type": authorizer_type,
                "authorizer_id": authorizer_id,
                "authorizer_agent_id": authorizer_agent_id,
                "authorizer_seq": authorizer_seq,
                "decision": decision,
                "condition": condition,
                "timestamp_ms": auth_timestamp,
            }
        )

    return {
        "parent_action_id": parent_action_id,
        "tool_name": tool_name,
        "parameters_hash": parameters_hash,
        "result_hash": result_hash,
        "result_status": result_status,
        "response_time_ms": response_time_ms,
        "protocol": protocol,
        "action_type": action_type,
        "target_entity": target_entity,
        "evidence_uri": evidence_uri,
        "redacted": redacted,
        "model_id": model_id,
        "input_token_count": input_token_count,
        "output_token_count": output_token_count,
        "authorization": {
            "type": auth_type,
            "entries": auth_entries,
        },
    }


def parse_boot_payload(payload_bytes: bytes) -> dict:
    """Parse BootPayload fields from canonical bytes."""
    offset = 0
    sdk_name, offset = _read_string(payload_bytes, offset)
    sdk_version, offset = _read_string(payload_bytes, offset)

    # Repeated string: interceptors
    interceptor_count = struct.unpack("<I", payload_bytes[offset : offset + 4])[0]
    offset += 4
    interceptors = []
    for _ in range(interceptor_count):
        s, offset = _read_string(payload_bytes, offset)
        interceptors.append(s)

    agent_framework, offset = _read_string(payload_bytes, offset)
    agent_name, offset = _read_string(payload_bytes, offset)
    runtime, offset = _read_string(payload_bytes, offset)
    chain_level = struct.unpack("<I", payload_bytes[offset : offset + 4])[0]
    offset += 4
    fsync_mode = struct.unpack("<I", payload_bytes[offset : offset + 4])[0]
    offset += 4
    clock_source, offset = _read_string(payload_bytes, offset)
    inference_recording = payload_bytes[offset] == 0x01
    offset += 1
    inference_evidence = payload_bytes[offset] == 0x01
    offset += 1
    evidence_recording = payload_bytes[offset] == 0x01
    offset += 1
    filter_config_hash = payload_bytes[offset : offset + 32]
    offset += 32
    matched_agent_rule, offset = _read_string(payload_bytes, offset)
    config_source, offset = _read_string(payload_bytes, offset)
    authorization_recording = payload_bytes[offset] == 0x01
    offset += 1

    return {
        "sdk_name": sdk_name,
        "sdk_version": sdk_version,
        "interceptors": interceptors,
        "agent_framework": agent_framework,
        "agent_name": agent_name,
        "runtime": runtime,
        "chain_level": chain_level,
        "fsync_mode": fsync_mode,
        "clock_source": clock_source,
        "inference_recording": inference_recording,
        "inference_evidence": inference_evidence,
        "evidence_recording": evidence_recording,
        "filter_config_hash": filter_config_hash,
        "matched_agent_rule": matched_agent_rule,
        "config_source": config_source,
        "authorization_recording": authorization_recording,
    }


def parse_gap_payload(payload_bytes: bytes) -> dict:
    """Parse GapPayload fields from canonical bytes after the envelope."""
    offset = 0
    first_lost_sequence = struct.unpack("<Q", payload_bytes[offset : offset + 8])[0]
    offset += 8
    last_lost_sequence = struct.unpack("<Q", payload_bytes[offset : offset + 8])[0]
    offset += 8
    count = struct.unpack("<Q", payload_bytes[offset : offset + 8])[0]
    offset += 8
    reason = struct.unpack("<I", payload_bytes[offset : offset + 4])[0]
    offset += 4
    detail, offset = _read_string(payload_bytes, offset)

    return {
        "first_lost_sequence": first_lost_sequence,
        "last_lost_sequence": last_lost_sequence,
        "count": count,
        "reason": reason,
        "detail": detail,
    }


def parse_checkpoint_payload(payload_bytes: bytes) -> dict:
    """Parse CheckpointPayload fields from canonical bytes after the envelope."""
    offset = 0
    record_count = struct.unpack("<Q", payload_bytes[offset : offset + 8])[0]
    offset += 8
    gap_count = struct.unpack("<Q", payload_bytes[offset : offset + 8])[0]
    offset += 8
    chain_hash = payload_bytes[offset : offset + 32]
    offset += 32
    merkle_root = payload_bytes[offset : offset + 32]
    offset += 32
    signature = payload_bytes[offset : offset + 64]
    offset += 64
    signing_key_id = payload_bytes[offset : offset + 32]
    offset += 32
    # EvidenceStatus (nested, inline)
    evidence_available = struct.unpack("<Q", payload_bytes[offset : offset + 8])[0]
    offset += 8
    evidence_exported = struct.unpack("<Q", payload_bytes[offset : offset + 8])[0]
    offset += 8
    evidence_expired = struct.unpack("<Q", payload_bytes[offset : offset + 8])[0]
    offset += 8
    evidence_missing = struct.unpack("<Q", payload_bytes[offset : offset + 8])[0]
    offset += 8

    return {
        "record_count": record_count,
        "gap_count": gap_count,
        "chain_hash": chain_hash,
        "merkle_root": merkle_root,
        "signature": signature,
        "signing_key_id": signing_key_id,
        "evidence_available": evidence_available,
        "evidence_exported": evidence_exported,
        "evidence_expired": evidence_expired,
        "evidence_missing": evidence_missing,
    }


def parse_recovery_payload(payload_bytes: bytes) -> dict:
    """Parse RecoveryPayload fields from canonical bytes after the envelope."""
    offset = 0
    records_verified = struct.unpack("<Q", payload_bytes[offset : offset + 8])[0]
    offset += 8
    records_truncated = struct.unpack("<Q", payload_bytes[offset : offset + 8])[0]
    offset += 8
    last_valid_seq = struct.unpack("<Q", payload_bytes[offset : offset + 8])[0]
    offset += 8
    recovery_method = struct.unpack("<I", payload_bytes[offset : offset + 4])[0]
    offset += 4
    detail, offset = _read_string(payload_bytes, offset)

    return {
        "records_verified": records_verified,
        "records_truncated": records_truncated,
        "last_valid_seq": last_valid_seq,
        "recovery_method": recovery_method,
        "detail": detail,
    }


def parse_key_payload(payload_bytes: bytes) -> dict:
    """Parse KeyPayload fields from canonical bytes after the envelope."""
    offset = 0
    public_key = payload_bytes[offset : offset + 32]
    offset += 32
    key_id = payload_bytes[offset : offset + 32]
    offset += 32
    expires_at = struct.unpack("<Q", payload_bytes[offset : offset + 8])[0]
    offset += 8
    supersedes_key_id = payload_bytes[offset : offset + 32]
    offset += 32

    return {
        "public_key": public_key,
        "key_id": key_id,
        "expires_at": expires_at,
        "supersedes_key_id": supersedes_key_id,
    }


def parse_witness_payload(payload_bytes: bytes) -> dict:
    """Parse WitnessPayload fields from canonical bytes after the envelope."""
    offset = 0
    witness_id, offset = _read_string(payload_bytes, offset)
    checkpoint_seq = struct.unpack("<Q", payload_bytes[offset : offset + 8])[0]
    offset += 8
    checkpoint_hash = payload_bytes[offset : offset + 32]
    offset += 32
    witness_timestamp = struct.unpack("<Q", payload_bytes[offset : offset + 8])[0]
    offset += 8
    receipt_signature = payload_bytes[offset : offset + 64]
    offset += 64
    witness_public_key = payload_bytes[offset : offset + 32]
    offset += 32

    return {
        "witness_id": witness_id,
        "checkpoint_seq": checkpoint_seq,
        "checkpoint_hash": checkpoint_hash,
        "witness_timestamp": witness_timestamp,
        "receipt_signature": receipt_signature,
        "witness_public_key": witness_public_key,
    }


def _read_string(data: bytes, offset: int) -> tuple[str, int]:
    """Read a length-prefixed UTF-8 string. Returns (string, new_offset)."""
    length = struct.unpack("<I", data[offset : offset + 4])[0]
    offset += 4
    s = data[offset : offset + length].decode("utf-8")
    offset += length
    return s, offset
