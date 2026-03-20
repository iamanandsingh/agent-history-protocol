"""Tests for crash recovery (scan_chain, recover_chain, truncate_chain)."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from ahp.core.chain import ChainWriter
from ahp.core.records import ActionPayload, Authorization
from ahp.core.recovery import recover_chain, scan_chain
from ahp.core.types import ActionType, AuthorizationType, Protocol, ResultStatus
from ahp.core.verify import verify_chain


class TestCrashRecovery(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.chain_path = os.path.join(self.tmpdir, "crash.ahp")

    def _write_n(self, n):
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

    def test_scan_clean_chain(self):
        self._write_n(5)
        result = scan_chain(self.chain_path)
        self.assertEqual(result.records_verified, 5)
        self.assertEqual(result.records_truncated, 0)
        self.assertEqual(result.last_valid_seq, 5)

    def test_scan_corrupt_tail(self):
        self._write_n(5)
        with open(self.chain_path, "ab") as f:
            f.write(b"\xff" * 50)

        result = scan_chain(self.chain_path)
        self.assertEqual(result.records_verified, 5)
        self.assertEqual(result.records_truncated, 1)

    def test_recover_truncates_corrupt(self):
        self._write_n(5)
        clean_size = Path(self.chain_path).stat().st_size

        with open(self.chain_path, "ab") as f:
            f.write(b"\xff" * 100)

        self.assertGreater(Path(self.chain_path).stat().st_size, clean_size)

        result = recover_chain(self.chain_path)
        self.assertEqual(result.records_verified, 5)
        self.assertEqual(result.records_truncated, 1)
        self.assertEqual(Path(self.chain_path).stat().st_size, clean_size)

        self.assertTrue(verify_chain(self.chain_path).valid)

    def test_recover_continues_chain(self):
        """After recovery, can continue writing to the chain."""
        self._write_n(3)
        with open(self.chain_path, "ab") as f:
            f.write(b"\xde\xad" * 25)

        result = recover_chain(self.chain_path)
        self.assertEqual(result.last_valid_seq, 3)

        writer2 = ChainWriter(self.chain_path)
        writer2._sequence = result.last_valid_seq
        writer2._prev_hash = result.last_prev_hash
        writer2._record_count = result.records_verified

        writer2.write_record(
            ActionPayload(
                tool_name="after_recovery",
                result_status=ResultStatus.SUCCESS,
                protocol=Protocol.MCP,
                action_type=ActionType.TOOL_CALL,
                authorization=Authorization(type=AuthorizationType.AUTH_NONE),
            )
        )
        writer2.close()

        verify_result = verify_chain(self.chain_path)
        self.assertTrue(verify_result.valid)
        self.assertEqual(verify_result.records_checked, 4)

    def test_scan_empty_file(self):
        writer = ChainWriter(self.chain_path)
        writer.close()
        result = scan_chain(self.chain_path)
        self.assertEqual(result.records_verified, 0)
        self.assertEqual(result.records_truncated, 0)

    def test_scan_nonexistent(self):
        result = scan_chain("/nonexistent/chain.ahp")
        self.assertEqual(result.records_verified, 0)


if __name__ == "__main__":
    unittest.main()
