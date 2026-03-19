"""Crash recovery — scan chain file, truncate corrupt records, resume.

Implements the recovery protocol from spec Section 3.6.
"""

from __future__ import annotations

import hashlib
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path

from ahp.core.chain import HEADER_SIZE, MAGIC, parse_envelope
from ahp.core.types import ZERO_HASH_32
from ahp.core.validation import MAX_RECORD_SIZE


@dataclass
class RecoveryResult:
    records_verified: int
    records_truncated: int
    last_valid_seq: int
    last_valid_offset: int  # file offset after last valid record
    last_prev_hash: bytes  # prev_hash for next record to continue chain


def scan_chain(path: str) -> RecoveryResult:
    """Scan a chain file and find the last valid record.

    Reads sequentially, verifying CRC of each record.
    Returns info about where the chain is valid up to.
    """
    p = Path(path)
    if not p.exists():
        return RecoveryResult(
            records_verified=0,
            records_truncated=0,
            last_valid_seq=0,
            last_valid_offset=HEADER_SIZE,
            last_prev_hash=ZERO_HASH_32,
        )

    records_verified = 0
    last_valid_seq = 0
    last_valid_offset = HEADER_SIZE
    last_stored_bytes = None

    with open(path, "rb") as f:
        header = f.read(HEADER_SIZE)
        if len(header) < HEADER_SIZE or header[:4] != MAGIC:
            return RecoveryResult(
                records_verified=0,
                records_truncated=0,
                last_valid_seq=0,
                last_valid_offset=0,
                last_prev_hash=ZERO_HASH_32,
            )

        while True:
            f.tell()

            length_bytes = f.read(4)
            if len(length_bytes) < 4:
                break

            length = struct.unpack("<I", length_bytes)[0]
            # Check for unreasonable length (corrupt data)
            if length > MAX_RECORD_SIZE:
                break  # Treat as corrupt
            stored = f.read(length)
            if len(stored) < length:
                break  # Truncated record

            crc_bytes = f.read(4)
            if len(crc_bytes) < 4:
                break

            expected_crc = struct.unpack("<I", crc_bytes)[0]
            actual_crc = zlib.crc32(length_bytes + stored) & 0xFFFFFFFF
            if actual_crc != expected_crc:
                break  # Corrupt CRC

            # Record is valid
            records_verified += 1
            last_valid_offset = f.tell()
            last_stored_bytes = stored

            try:
                env = parse_envelope(stored)
                last_valid_seq = env["sequence"]
            except Exception:
                pass

    # Compute prev_hash for continuation
    if last_stored_bytes:
        last_prev_hash = hashlib.sha256(last_stored_bytes).digest()
    else:
        last_prev_hash = ZERO_HASH_32

    # Count corrupt trailing segments (bytes after last valid record).
    # We estimate the number of lost records by counting how many
    # length+CRC frames (complete or partial) appear in the corrupt tail.
    file_size = p.stat().st_size
    truncated = 0
    if file_size > last_valid_offset:
        corrupt_bytes = file_size - last_valid_offset
        if records_verified > 0:
            # Estimate average record frame size (4B length + payload + 4B CRC)
            avg_record_frame = (last_valid_offset - HEADER_SIZE) / records_verified
            truncated = max(1, round(corrupt_bytes / avg_record_frame))
        else:
            # No valid records to estimate from — at least one corrupt segment
            truncated = 1

    return RecoveryResult(
        records_verified=records_verified,
        records_truncated=truncated,
        last_valid_seq=last_valid_seq,
        last_valid_offset=last_valid_offset,
        last_prev_hash=last_prev_hash,
    )


def truncate_chain(path: str, valid_offset: int) -> None:
    """Truncate chain file to remove corrupt trailing data."""
    with open(path, "r+b") as f:
        f.truncate(valid_offset)


def recover_chain(path: str) -> RecoveryResult:
    """Full recovery: scan + truncate corrupt tail.

    Returns the recovery result. Caller should emit RecoveryRecord + GapRecord.
    """
    result = scan_chain(path)

    if result.records_truncated > 0:
        truncate_chain(path, result.last_valid_offset)

    return result
