"""UUID v7 generation — time-ordered UUIDs per RFC 9562."""

import os
import time


def uuid7() -> bytes:
    """Generate a UUID v7 as 16 raw bytes.

    Layout (128 bits):
      48 bits: unix_ts_ms (milliseconds since epoch)
       4 bits: version (0b0111 = 7)
      12 bits: rand_a
       2 bits: variant (0b10)
      62 bits: rand_b
    """
    ts_ms = int(time.time() * 1000)
    rand_bytes = os.urandom(10)

    # Bytes 0-5: timestamp (48 bits, big-endian)
    b = bytearray(16)
    b[0] = (ts_ms >> 40) & 0xFF
    b[1] = (ts_ms >> 32) & 0xFF
    b[2] = (ts_ms >> 24) & 0xFF
    b[3] = (ts_ms >> 16) & 0xFF
    b[4] = (ts_ms >> 8) & 0xFF
    b[5] = ts_ms & 0xFF

    # Bytes 6-7: version (4 bits) + rand_a (12 bits)
    b[6] = 0x70 | (rand_bytes[0] & 0x0F)  # version 7
    b[7] = rand_bytes[1]

    # Bytes 8-15: variant (2 bits) + rand_b (62 bits)
    b[8] = 0x80 | (rand_bytes[2] & 0x3F)  # variant 10
    b[9] = rand_bytes[3]
    b[10] = rand_bytes[4]
    b[11] = rand_bytes[5]
    b[12] = rand_bytes[6]
    b[13] = rand_bytes[7]
    b[14] = rand_bytes[8]
    b[15] = rand_bytes[9]

    return bytes(b)


def uuid7_to_str(raw: bytes) -> str:
    """Convert 16 raw UUID bytes to standard hyphenated string."""
    h = raw.hex()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


def str_to_uuid7(s: str) -> bytes:
    """Convert hyphenated UUID string to 16 raw bytes."""
    return bytes.fromhex(s.replace("-", ""))
