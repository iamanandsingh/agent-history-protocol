"""Sprint 1 tests: streaming reader, file locking, crash recovery, PII presets."""
from __future__ import annotations

import os
import struct
import tempfile
import unittest
import zlib
from pathlib import Path

from ahp.core.types import (
    ResultStatus, Protocol, ActionType, AuthorizationType, GapReason,
)
from ahp.core.records import ActionPayload, BootPayload, Authorization
from ahp.core.chain import ChainWriter, ChainReader, parse_envelope
from ahp.core.verify import verify_chain
from ahp.core.recovery import scan_chain, recover_chain, truncate_chain


class TestStreamingReader(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.chain_path = os.path.join(self.tmpdir, "stream.ahp")

    def _write_n_records(self, n):
        writer = ChainWriter(self.chain_path)
        for i in range(n):
            writer.write_record(ActionPayload(
                tool_name=f"tool_{i}",
                result_status=ResultStatus.SUCCESS,
                protocol=Protocol.MCP,
                action_type=ActionType.TOOL_CALL,
                authorization=Authorization(type=AuthorizationType.AUTH_NONE),
            ))
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
        # Create chain with just header
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
            self.assertGreaterEqual(env['sequence'], 5)
            self.assertLessEqual(env['sequence'], 10)

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
                writer2 = ChainWriter(self.chain_path)
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


class TestCrashRecovery(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.chain_path = os.path.join(self.tmpdir, "crash.ahp")

    def test_scan_clean_chain(self):
        writer = ChainWriter(self.chain_path)
        for i in range(5):
            writer.write_record(ActionPayload(
                tool_name=f"tool_{i}",
                result_status=ResultStatus.SUCCESS,
                protocol=Protocol.MCP,
                action_type=ActionType.TOOL_CALL,
                authorization=Authorization(type=AuthorizationType.AUTH_NONE),
            ))
        writer.close()

        result = scan_chain(self.chain_path)
        self.assertEqual(result.records_verified, 5)
        self.assertEqual(result.records_truncated, 0)
        self.assertEqual(result.last_valid_seq, 5)

    def test_scan_corrupt_tail(self):
        writer = ChainWriter(self.chain_path)
        for i in range(5):
            writer.write_record(ActionPayload(
                tool_name=f"tool_{i}",
                result_status=ResultStatus.SUCCESS,
                protocol=Protocol.MCP,
                action_type=ActionType.TOOL_CALL,
                authorization=Authorization(type=AuthorizationType.AUTH_NONE),
            ))
        writer.close()

        # Append garbage bytes (simulates partial write during crash)
        with open(self.chain_path, 'ab') as f:
            f.write(b'\xff' * 50)

        result = scan_chain(self.chain_path)
        self.assertEqual(result.records_verified, 5)
        self.assertEqual(result.records_truncated, 1)

    def test_recover_truncates_corrupt(self):
        writer = ChainWriter(self.chain_path)
        for i in range(5):
            writer.write_record(ActionPayload(
                tool_name=f"tool_{i}",
                result_status=ResultStatus.SUCCESS,
                protocol=Protocol.MCP,
                action_type=ActionType.TOOL_CALL,
                authorization=Authorization(type=AuthorizationType.AUTH_NONE),
            ))
        writer.close()

        # Get file size before corruption
        clean_size = Path(self.chain_path).stat().st_size

        # Append garbage
        with open(self.chain_path, 'ab') as f:
            f.write(b'\xff' * 100)

        corrupt_size = Path(self.chain_path).stat().st_size
        self.assertGreater(corrupt_size, clean_size)

        # Recover
        result = recover_chain(self.chain_path)
        self.assertEqual(result.records_verified, 5)
        self.assertEqual(result.records_truncated, 1)

        # File should be truncated back
        recovered_size = Path(self.chain_path).stat().st_size
        self.assertEqual(recovered_size, clean_size)

        # Chain should be valid after recovery
        verify_result = verify_chain(self.chain_path)
        self.assertTrue(verify_result.valid)

    def test_recover_continues_chain(self):
        """After recovery, can continue writing to the chain."""
        writer = ChainWriter(self.chain_path)
        for i in range(3):
            writer.write_record(ActionPayload(
                tool_name=f"tool_{i}",
                result_status=ResultStatus.SUCCESS,
                protocol=Protocol.MCP,
                action_type=ActionType.TOOL_CALL,
                authorization=Authorization(type=AuthorizationType.AUTH_NONE),
            ))
        writer.close()

        # Corrupt
        with open(self.chain_path, 'ab') as f:
            f.write(b'\xde\xad' * 25)

        # Recover
        result = recover_chain(self.chain_path)
        self.assertEqual(result.last_valid_seq, 3)

        # Continue writing — need a new writer that picks up from last state
        # The writer needs to know the last sequence and prev_hash
        writer2 = ChainWriter(self.chain_path)
        writer2._sequence = result.last_valid_seq
        writer2._prev_hash = result.last_prev_hash
        writer2._record_count = result.records_verified

        writer2.write_record(ActionPayload(
            tool_name="after_recovery",
            result_status=ResultStatus.SUCCESS,
            protocol=Protocol.MCP,
            action_type=ActionType.TOOL_CALL,
            authorization=Authorization(type=AuthorizationType.AUTH_NONE),
        ))
        writer2.close()

        # Verify full chain
        verify_result = verify_chain(self.chain_path)
        self.assertTrue(verify_result.valid)
        self.assertEqual(verify_result.records_checked, 4)

    def test_scan_empty_file(self):
        # Create empty chain (just header)
        writer = ChainWriter(self.chain_path)
        writer.close()

        result = scan_chain(self.chain_path)
        self.assertEqual(result.records_verified, 0)
        self.assertEqual(result.records_truncated, 0)

    def test_scan_nonexistent(self):
        result = scan_chain("/nonexistent/chain.ahp")
        self.assertEqual(result.records_verified, 0)


if __name__ == '__main__':
    unittest.main()
