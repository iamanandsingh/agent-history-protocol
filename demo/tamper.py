"""Tamper with a record in the chain — demonstrates tamper detection.

This script modifies record #3 (search_orders) to change the tool_name
to "search_docs", simulating an attacker trying to hide that customer
order data was accessed.
"""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

CHAIN_FILE = "support-bot.ahp"
HEADER_SIZE = 16  # AHP file header


def main():
    if not Path(CHAIN_FILE).exists():
        print(f"Chain file not found: {CHAIN_FILE}")
        print("Run demo/agent.py first.")
        sys.exit(1)

    print("\n⚠  Tampering with the chain...\n")

    with open(CHAIN_FILE, 'rb') as f:
        data = bytearray(f.read())

    # Navigate to record #3 (0-indexed: skip header, then skip records 1 and 2)
    offset = HEADER_SIZE
    target_record = 3  # 1-indexed

    for i in range(1, target_record):
        length = struct.unpack('<I', data[offset:offset+4])[0]
        offset += 4 + length + 4  # length + record + crc

    # Now offset points to record #3's length prefix
    length = struct.unpack('<I', data[offset:offset+4])[0]
    record_start = offset + 4  # skip length prefix

    # Find "search_orders" in the record bytes and replace with "search_docs__"
    # (same length to keep offsets valid)
    original = b'search_orders'
    replacement = b'search_docs__'

    record_bytes = data[record_start:record_start + length]
    pos = record_bytes.find(original)

    if pos == -1:
        print("Could not find 'search_orders' in record #3.")
        print("Make sure you run demo/agent.py first.")
        sys.exit(1)

    print(f"  Record #3: Changing tool_name")
    print(f"    FROM: \"search_orders\"")
    print(f"    TO:   \"search_docs__\"\n")
    print("  (Simulating: attacker hides that customer order data was accessed)\n")

    # Modify the bytes
    data[record_start + pos:record_start + pos + len(original)] = replacement

    # A real attacker would fix the CRC (trivial) but can't fix the hash chain
    # Recalculate CRC for the tampered record
    import zlib
    length_bytes = data[offset:offset+4]
    record_bytes_new = bytes(data[record_start:record_start + length])
    new_crc = zlib.crc32(length_bytes + record_bytes_new) & 0xFFFFFFFF
    crc_offset = record_start + length
    struct.pack_into('<I', data, crc_offset, new_crc)

    with open(CHAIN_FILE, 'wb') as f:
        f.write(data)

    print("  Done. Record #3 has been modified.\n")
    print("  Now run:")
    print(f"    python -m ahp.cli.main verify --chain {CHAIN_FILE}\n")


if __name__ == '__main__':
    main()
