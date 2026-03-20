"""Tests for ChainReader streaming operations and file locking."""

from __future__ import annotations

import os
import tempfile
import unittest

from ahp.core.chain import ChainReader, ChainWriter, parse_envelope
from ahp.core.records import ActionPayload, Authorization, BootPayload
from ahp.core.types import ActionType, AuthorizationType, Protocol, ResultStatus


class TestStreamingReader(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.chain_path = os.path.join(self.tmpdir, "stream.ahp")

    def _write_n_records(self, n):
        writer = ChainWriter(self.chain_path)
        for i in range(n):
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
        return writer

    def test_iter_records(self):
        self._write_n_records(10)
        reader = ChainReader(self.chain_path)
        count = 0
        for stored in reader.iter_records():
            self.assertIsInstance(stored, bytes)
            count += 1
        self.assertEqual(count, 10)

    def test_iter_empty_chain(self):
        writer = ChainWriter(self.chain_path)
        writer.close()
        reader = ChainReader(self.chain_path)
        self.assertEqual(list(reader.iter_records()), [])

    def test_iter_matches_read_all(self):
        self._write_n_records(20)
        reader = ChainReader(self.chain_path)
        iterated = list(reader.iter_records())
        all_records = reader.read_all()
        self.assertEqual(iterated, all_records)

    def test_read_range(self):
        self._write_n_records(20)
        reader = ChainReader(self.chain_path)
        records = reader.read_range(5, 10)
        self.assertEqual(len(records), 6)
        for stored in records:
            env = parse_envelope(stored)
            self.assertGreaterEqual(env["sequence"], 5)
            self.assertLessEqual(env["sequence"], 10)

    def test_read_range_beyond(self):
        self._write_n_records(20)
        reader = ChainReader(self.chain_path)
        records = reader.read_range(18, 25)
        self.assertEqual(len(records), 3)  # 18, 19, 20

    def test_count(self):
        self._write_n_records(15)
        reader = ChainReader(self.chain_path)
        self.assertEqual(reader.count(), 15)

    def test_large_chain_iter(self):
        self._write_n_records(1000)
        reader = ChainReader(self.chain_path)
        count = sum(1 for _ in reader.iter_records())
        self.assertEqual(count, 1000)


class TestFileLocking(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.chain_path = os.path.join(self.tmpdir, "locked.ahp")

    def test_lock_prevents_dual_writer(self):
        writer1 = ChainWriter(self.chain_path)
        try:
            with self.assertRaises(RuntimeError) as ctx:
                ChainWriter(self.chain_path)
            self.assertIn("locked", str(ctx.exception).lower())
        except unittest.SkipTest:
            pass  # fcntl not available
        except RuntimeError:
            pass  # Expected
        finally:
            writer1.close()

    def test_lock_released_on_close(self):
        writer1 = ChainWriter(self.chain_path)
        writer1.write_record(BootPayload(agent_name="test"))
        writer1.close()

        # Should be able to open again
        writer2 = ChainWriter(self.chain_path)
        writer2.close()


if __name__ == "__main__":
    unittest.main()
