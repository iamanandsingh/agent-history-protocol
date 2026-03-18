"""Tests for chain file rotation."""
from __future__ import annotations

import os
import tempfile
import unittest

from ahp.core.types import ResultStatus, Protocol, ActionType, AuthorizationType
from ahp.core.records import ActionPayload, Authorization
from ahp.core.chain import ChainReader
from ahp.core.verify import verify_chain
from ahp.core.rotation import ChainRotator


class TestChainRotation(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def _make_payload(self, i: int) -> ActionPayload:
        return ActionPayload(
            tool_name=f"tool_{i}",
            result_status=ResultStatus.SUCCESS,
            protocol=Protocol.MCP,
            action_type=ActionType.TOOL_CALL,
            authorization=Authorization(type=AuthorizationType.AUTH_NONE),
        )

    def test_single_segment(self):
        rotator = ChainRotator("test", self.tmpdir)
        writer = rotator.get_writer()
        for i in range(10):
            writer.write_record(self._make_payload(i))

        self.assertEqual(rotator.segment_count, 1)
        self.assertFalse(rotator.needs_rotation())
        rotator.close()

    def test_rotation_at_size_limit(self):
        # Use a tiny limit to trigger rotation quickly
        rotator = ChainRotator("test", self.tmpdir, max_segment_bytes=1024)
        writer = rotator.get_writer()

        # Write until rotation needed
        for i in range(50):
            writer.write_record(self._make_payload(i))
            if rotator.needs_rotation():
                writer = rotator.rotate()

        self.assertGreater(rotator.segment_count, 1)
        rotator.close()

    def test_each_segment_valid(self):
        rotator = ChainRotator("test", self.tmpdir, max_segment_bytes=1024)
        writer = rotator.get_writer()

        for i in range(50):
            writer.write_record(self._make_payload(i))
            if rotator.needs_rotation():
                writer = rotator.rotate()

        rotator.close()

        # Each segment should be a valid chain
        for seg in rotator.segments:
            if seg.exists:
                result = verify_chain(seg.path)
                self.assertTrue(result.valid, f"Segment {seg.index} invalid: {result.error}")

    def test_export_gated_deletion(self):
        rotator = ChainRotator("test", self.tmpdir, max_segment_bytes=512)
        writer = rotator.get_writer()

        for i in range(30):
            writer.write_record(self._make_payload(i))
            if rotator.needs_rotation():
                writer = rotator.rotate()

        rotator.close()

        initial_count = rotator.segment_count
        self.assertGreater(initial_count, 1)

        # Compact without marking exported — nothing should be removed
        removed = rotator.compact()
        self.assertEqual(removed, 0)

        # Mark first segment as exported
        if rotator.segments:
            rotator.mark_exported(rotator.segments[0].index)
            removed = rotator.compact()
            self.assertEqual(removed, 1)
            self.assertEqual(rotator.segment_count, initial_count - 1)

    def test_total_records(self):
        rotator = ChainRotator("test", self.tmpdir, max_segment_bytes=1024)
        writer = rotator.get_writer()
        total_written = 0
        for i in range(40):
            writer.write_record(self._make_payload(i))
            total_written += 1
            if rotator.needs_rotation():
                writer = rotator.rotate()

        rotator.close()

        # Update counts
        for seg in rotator.segments:
            seg.record_count = ChainReader(seg.path).count()

        self.assertEqual(rotator.total_records, total_written)

    def test_discover_existing_segments(self):
        # Create segments
        rotator1 = ChainRotator("test", self.tmpdir, max_segment_bytes=512)
        writer = rotator1.get_writer()
        for i in range(20):
            writer.write_record(self._make_payload(i))
            if rotator1.needs_rotation():
                writer = rotator1.rotate()
        rotator1.close()
        count1 = rotator1.segment_count

        # Re-open — should discover existing segments
        rotator2 = ChainRotator("test", self.tmpdir, max_segment_bytes=512)
        self.assertEqual(rotator2.segment_count, count1)


if __name__ == '__main__':
    unittest.main()
