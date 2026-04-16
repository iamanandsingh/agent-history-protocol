"""Core protocol tests — canonical serialization, hash chain, verification."""

from __future__ import annotations

import hashlib
import os
import tempfile
import unittest

from ahp.core.canonical import canonical_bytes
from ahp.core.chain import ChainReader, ChainWriter, parse_envelope
from ahp.core.json_format import record_to_json
from ahp.core.records import (
    ActionPayload,
    Authorization,
    AuthorizationEntry,
    BootPayload,
    Record,
)
from ahp.core.types import (
    SCHEMA_VERSION,
    ZERO_HASH_32,
    ActionType,
    AuthorizationDecision,
    AuthorizationType,
    AuthorizerType,
    Protocol,
    RecordType,
    ResultStatus,
)
from ahp.core.uuid7 import str_to_uuid7, uuid7, uuid7_to_str
from ahp.core.verify import verify_chain


class TestUUID7(unittest.TestCase):
    def test_length(self):
        u = uuid7()
        self.assertEqual(len(u), 16)

    def test_version_bits(self):
        u = uuid7()
        # Byte 6 high nibble should be 0x7
        self.assertEqual((u[6] >> 4) & 0xF, 7)

    def test_variant_bits(self):
        u = uuid7()
        # Byte 8 high 2 bits should be 10
        self.assertEqual((u[8] >> 6) & 0x3, 2)

    def test_round_trip(self):
        u = uuid7()
        s = uuid7_to_str(u)
        self.assertEqual(len(s), 36)  # 8-4-4-4-12 with hyphens
        u2 = str_to_uuid7(s)
        self.assertEqual(u, u2)

    def test_uniqueness(self):
        uuids = {uuid7() for _ in range(100)}
        self.assertEqual(len(uuids), 100)


class TestCanonicalSerialization(unittest.TestCase):
    def _make_action_record(self, **overrides):
        fields = dict(
            record_id=b"\x01" * 16,
            agent_id=b"\x02" * 16,
            session_id=b"\x03" * 16,
            timestamp_ms=1710000000000,
            sequence=1,
            prev_hash=ZERO_HASH_32,
            schema_version=SCHEMA_VERSION,
            record_type=RecordType.ACTION,
            payload=ActionPayload(
                tool_name="read_file",
                parameters_hash=b"\xaa" * 16,
                result_hash=b"\xbb" * 16,
                result_status=ResultStatus.SUCCESS,
                response_time_ms=42,
                protocol=Protocol.MCP,
                action_type=ActionType.TOOL_CALL,
                authorization=Authorization(type=AuthorizationType.AUTH_NONE),
            ),
        )
        fields.update(overrides)
        return Record(**fields)

    def test_deterministic(self):
        r = self._make_action_record()
        b1 = canonical_bytes(r)
        b2 = canonical_bytes(r)
        self.assertEqual(b1, b2)

    def test_different_data_different_bytes(self):
        r1 = self._make_action_record()
        r2 = self._make_action_record(
            payload=ActionPayload(
                tool_name="write_file",
                result_status=ResultStatus.SUCCESS,
                protocol=Protocol.MCP,
                action_type=ActionType.TOOL_CALL,
                authorization=Authorization(type=AuthorizationType.AUTH_NONE),
            ),
        )
        self.assertNotEqual(canonical_bytes(r1), canonical_bytes(r2))

    def test_auth_changes_bytes(self):
        r1 = self._make_action_record()
        r2 = self._make_action_record(
            payload=ActionPayload(
                tool_name="read_file",
                parameters_hash=b"\xaa" * 16,
                result_hash=b"\xbb" * 16,
                result_status=ResultStatus.SUCCESS,
                response_time_ms=42,
                protocol=Protocol.MCP,
                action_type=ActionType.TOOL_CALL,
                authorization=Authorization(
                    type=AuthorizationType.AUTH_HUMAN,
                    entries=[
                        AuthorizationEntry(
                            authorizer_type=AuthorizerType.AUTHORIZER_HUMAN,
                            authorizer_id="user:test",
                            decision=AuthorizationDecision.APPROVED,
                            timestamp_ms=1710000000000,
                        )
                    ],
                ),
            ),
        )
        self.assertNotEqual(canonical_bytes(r1), canonical_bytes(r2))

    def test_boot_record(self):
        r = Record(
            record_id=b"\x01" * 16,
            agent_id=b"\x02" * 16,
            session_id=b"\x03" * 16,
            timestamp_ms=1710000000000,
            sequence=1,
            prev_hash=ZERO_HASH_32,
            schema_version=SCHEMA_VERSION,
            record_type=RecordType.BOOT,
            payload=BootPayload(
                agent_name="test-agent",
                authorization_recording=True,
            ),
        )
        b = canonical_bytes(r)
        self.assertIsInstance(b, bytes)
        self.assertGreater(len(b), 100)


class TestChainWriterReader(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.chain_path = os.path.join(self.tmpdir, "test.ahp")

    def test_write_and_read(self):
        writer = ChainWriter(self.chain_path)
        writer.write_record(BootPayload(agent_name="test"))
        writer.write_record(
            ActionPayload(
                tool_name="test_tool",
                result_status=ResultStatus.SUCCESS,
                protocol=Protocol.MCP,
                action_type=ActionType.TOOL_CALL,
                authorization=Authorization(type=AuthorizationType.AUTH_NONE),
            )
        )

        reader = ChainReader(self.chain_path)
        records = reader.read_all()
        self.assertEqual(len(records), 2)

    def test_hash_chain_integrity(self):
        writer = ChainWriter(self.chain_path)
        for i in range(5):
            writer.write_record(
                ActionPayload(
                    tool_name=f"tool_{i}",
                    result_status=ResultStatus.SUCCESS,
                    protocol=Protocol.MCP,
                    action_type=ActionType.TOOL_CALL,
                    authorization=Authorization(type=AuthorizationType.AUTH_NONE),
                )
            )

        reader = ChainReader(self.chain_path)
        records = reader.read_all()

        # Verify chain manually
        for i in range(1, len(records)):
            env = parse_envelope(records[i])
            expected = hashlib.sha256(records[i - 1]).digest()
            self.assertEqual(env["prev_hash"], expected)

    def test_sequence_monotonic(self):
        writer = ChainWriter(self.chain_path)
        for i in range(5):
            writer.write_record(
                ActionPayload(
                    tool_name=f"tool_{i}",
                    result_status=ResultStatus.SUCCESS,
                    protocol=Protocol.MCP,
                    action_type=ActionType.TOOL_CALL,
                    authorization=Authorization(type=AuthorizationType.AUTH_NONE),
                )
            )

        reader = ChainReader(self.chain_path)
        records = reader.read_all()
        for i, stored in enumerate(records):
            env = parse_envelope(stored)
            self.assertEqual(env["sequence"], i + 1)

    def test_timestamp_monotonic_across_records(self):
        """Each record's timestamp_ms must be >= the previous record's."""
        writer = ChainWriter(self.chain_path)
        for i in range(10):
            writer.write_record(
                ActionPayload(
                    tool_name=f"tool_{i}",
                    result_status=ResultStatus.SUCCESS,
                    protocol=Protocol.MCP,
                    action_type=ActionType.TOOL_CALL,
                    authorization=Authorization(type=AuthorizationType.AUTH_NONE),
                )
            )
        writer.close()

        reader = ChainReader(self.chain_path)
        prev_ts = 0
        count = 0
        for stored in reader.iter_records():
            env = parse_envelope(stored)
            self.assertGreaterEqual(env["timestamp_ms"], prev_ts)
            prev_ts = env["timestamp_ms"]
            count += 1
        self.assertEqual(count, 10)

    def test_timestamp_floored_across_backward_clock_step(self):
        """A backward wall-clock step (NTP adjustment, VM resume, manual
        clock change) must not produce non-monotonic timestamps in the
        chain. The writer applies a monotonic non-decreasing floor so
        record N+1's timestamp is always >= record N's.
        """
        import time as real_time
        import unittest.mock

        writer = ChainWriter(self.chain_path)
        # Replace chain.py's module-level `time` reference with a shim that
        # only controls time.time(); other attributes (e.g. sleep) fall
        # through. This avoids affecting uuid7's unrelated time.time() use.
        mock_time = unittest.mock.MagicMock(wraps=real_time)
        mock_time.time = unittest.mock.Mock(side_effect=[2.0, 1.0, 2.5])
        with unittest.mock.patch("ahp.core.chain.time", mock_time):
            for name in ("first", "second", "third"):
                writer.write_record(
                    ActionPayload(
                        tool_name=name,
                        result_status=ResultStatus.SUCCESS,
                        protocol=Protocol.MCP,
                        action_type=ActionType.TOOL_CALL,
                        authorization=Authorization(type=AuthorizationType.AUTH_NONE),
                    )
                )
        writer.close()

        reader = ChainReader(self.chain_path)
        timestamps = [parse_envelope(s)["timestamp_ms"] for s in reader.iter_records()]
        self.assertEqual(timestamps[0], 2000, "first record uses wall clock")
        self.assertEqual(
            timestamps[1], 2000,
            "backward step must floor to previous ts, not regress to 1000",
        )
        self.assertEqual(timestamps[2], 2500, "wall clock moving forward again is honored")


class TestVerification(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.chain_path = os.path.join(self.tmpdir, "test.ahp")

    def test_valid_chain(self):
        writer = ChainWriter(self.chain_path)
        writer.write_record(BootPayload(agent_name="test"))
        writer.write_record(
            ActionPayload(
                tool_name="test",
                result_status=ResultStatus.SUCCESS,
                protocol=Protocol.MCP,
                action_type=ActionType.TOOL_CALL,
                authorization=Authorization(type=AuthorizationType.AUTH_NONE),
            )
        )

        result = verify_chain(self.chain_path)
        self.assertTrue(result.valid)
        self.assertEqual(result.records_checked, 2)
        self.assertEqual(result.gaps, 0)

    def test_tampered_chain(self):
        writer = ChainWriter(self.chain_path)
        writer.write_record(BootPayload(agent_name="test"))
        writer.write_record(
            ActionPayload(
                tool_name="original_tool",
                result_status=ResultStatus.SUCCESS,
                protocol=Protocol.MCP,
                action_type=ActionType.TOOL_CALL,
                authorization=Authorization(type=AuthorizationType.AUTH_NONE),
            )
        )
        writer.write_record(
            ActionPayload(
                tool_name="another_tool",
                result_status=ResultStatus.SUCCESS,
                protocol=Protocol.MCP,
                action_type=ActionType.TOOL_CALL,
                authorization=Authorization(type=AuthorizationType.AUTH_NONE),
            )
        )

        # Tamper with record #2 (change a byte in the stored bytes)
        import struct
        import zlib

        with open(self.chain_path, "rb") as f:
            data = bytearray(f.read())

        # Skip header (16 bytes) and first record
        offset = 16
        length1 = struct.unpack("<I", data[offset : offset + 4])[0]
        offset += 4 + length1 + 4  # length + record + crc

        # Now at record #2 — modify a byte in the record
        length2 = struct.unpack("<I", data[offset : offset + 4])[0]
        record_start = offset + 4
        data[record_start + 50] ^= 0xFF  # flip a byte

        # Fix CRC for the tampered record
        length_bytes = data[offset : offset + 4]
        record_bytes = bytes(data[record_start : record_start + length2])
        new_crc = zlib.crc32(length_bytes + record_bytes) & 0xFFFFFFFF
        crc_offset = record_start + length2
        struct.pack_into("<I", data, crc_offset, new_crc)

        with open(self.chain_path, "wb") as f:
            f.write(data)

        result = verify_chain(self.chain_path)
        self.assertFalse(result.valid)
        self.assertIsNotNone(result.broken_at)

    def test_truncated_chain_is_detected(self):
        """Truncating the tail of a chain file must fail verification.

        Without truncation detection, iter_records silently stops at the
        cut, verify_chain validates the readable prefix, and returns
        valid=True — hiding every record after the cut from the auditor.
        """
        writer = ChainWriter(self.chain_path)
        for i in range(4):
            writer.write_record(
                ActionPayload(
                    tool_name=f"tool_{i}",
                    result_status=ResultStatus.SUCCESS,
                    protocol=Protocol.MCP,
                    action_type=ActionType.TOOL_CALL,
                    authorization=Authorization(type=AuthorizationType.AUTH_NONE),
                )
            )
        writer.close()

        file_size = os.path.getsize(self.chain_path)
        with open(self.chain_path, "r+b") as f:
            f.truncate(file_size - 20)  # cut off tail mid-record

        result = verify_chain(self.chain_path)
        self.assertFalse(result.valid, "Tail truncation must be detected")
        self.assertIsNotNone(result.error)
        err = result.error.lower()
        # Depending on whether the cut lands in the body, the CRC, or the
        # length prefix, the error wording differs — all three are valid
        # "the tail was chopped off" signals.
        self.assertTrue(
            "truncat" in err or "crc" in err or "missing" in err,
            f"Error did not describe truncation-family corruption: {result.error!r}",
        )

    def test_flipped_byte_without_crc_fix_is_detected(self):
        """A corrupted record that does NOT have its CRC recomputed must
        still fail verification — not silently stop the iterator and pass.
        """
        writer = ChainWriter(self.chain_path)
        writer.write_record(BootPayload(agent_name="test"))
        for i in range(3):
            writer.write_record(
                ActionPayload(
                    tool_name=f"tool_{i}",
                    result_status=ResultStatus.SUCCESS,
                    protocol=Protocol.MCP,
                    action_type=ActionType.TOOL_CALL,
                    authorization=Authorization(type=AuthorizationType.AUTH_NONE),
                )
            )
        writer.close()

        # Flip one byte in the 3rd record body, leaving CRC intact → bad CRC.
        import struct as _struct

        with open(self.chain_path, "rb") as f:
            data = bytearray(f.read())

        offset = 16  # skip header
        for _ in range(2):  # skip the first two records
            rec_len = _struct.unpack("<I", data[offset : offset + 4])[0]
            offset += 4 + rec_len + 4

        # Flip a byte inside the body of record #3
        data[offset + 4 + 10] ^= 0x5A

        with open(self.chain_path, "wb") as f:
            f.write(data)

        result = verify_chain(self.chain_path)
        self.assertFalse(result.valid, "Mid-chain CRC corruption must be detected")
        self.assertIsNotNone(result.error)

    def test_empty_chain(self):
        # Create file with just header
        import struct

        with open(self.chain_path, "wb") as f:
            f.write(b"AHP\x00")
            f.write(struct.pack("<I", 1))
            f.write(struct.pack("<Q", 0))

        result = verify_chain(self.chain_path)
        self.assertTrue(result.valid)
        self.assertEqual(result.records_checked, 0)


class TestJsonFormat(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.chain_path = os.path.join(self.tmpdir, "test.ahp")

    def test_action_to_json(self):
        writer = ChainWriter(self.chain_path)
        writer.write_record(
            ActionPayload(
                tool_name="test_tool",
                result_status=ResultStatus.SUCCESS,
                response_time_ms=42,
                protocol=Protocol.MCP,
                action_type=ActionType.TOOL_CALL,
                authorization=Authorization(
                    type=AuthorizationType.AUTH_HUMAN,
                    entries=[
                        AuthorizationEntry(
                            authorizer_type=AuthorizerType.AUTHORIZER_HUMAN,
                            authorizer_id="user:test",
                            decision=AuthorizationDecision.APPROVED,
                            timestamp_ms=1710000000000,
                        )
                    ],
                ),
            )
        )

        reader = ChainReader(self.chain_path)
        records = reader.read_all()
        j = record_to_json(records[0])

        self.assertEqual(j["type"], "ACTION")
        self.assertEqual(j["payload"]["tool_name"], "test_tool")
        self.assertEqual(j["payload"]["authorization"]["type"], "AUTH_HUMAN")
        self.assertEqual(len(j["payload"]["authorization"]["entries"]), 1)
        self.assertEqual(j["payload"]["authorization"]["entries"][0]["authorizer_id"], "user:test")
        self.assertEqual(j["payload"]["authorization"]["entries"][0]["decision"], "APPROVED")

    def test_boot_to_json(self):
        writer = ChainWriter(self.chain_path)
        writer.write_record(
            BootPayload(
                agent_name="test-bot",
                authorization_recording=True,
            )
        )

        reader = ChainReader(self.chain_path)
        records = reader.read_all()
        j = record_to_json(records[0])

        self.assertEqual(j["type"], "BOOT")
        self.assertEqual(j["payload"]["agent_name"], "test-bot")
        self.assertTrue(j["payload"]["authorization_recording"])


if __name__ == "__main__":
    unittest.main()
