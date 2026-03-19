"""Complete chain tests — gap, recovery, checkpoint, threading, multi-session."""
from __future__ import annotations

import hashlib
import os
import struct
import tempfile
import threading
import unittest
import zlib
from typing import Optional

from ahp.core.types import (
    RecordType, ResultStatus, Protocol, ActionType,
    AuthorizationType, GapReason, RecoveryMethod,
    ZERO_HASH_32, SCHEMA_VERSION,
)
from ahp.core.records import (
    ActionPayload, BootPayload, GapPayload, CheckpointPayload,
    RecoveryPayload, Authorization,
)
from ahp.core.chain import (
    ChainWriter, ChainReader, parse_envelope, parse_gap_payload,
    parse_checkpoint_payload, HEADER_SIZE,
)
from ahp.core.verify import verify_chain
from ahp.core.canonical import canonical_bytes


def _action(tool_name: str = "test_tool") -> ActionPayload:
    """Helper to create a simple ActionPayload."""
    return ActionPayload(
        tool_name=tool_name,
        result_status=ResultStatus.SUCCESS,
        protocol=Protocol.MCP,
        action_type=ActionType.TOOL_CALL,
        authorization=Authorization(type=AuthorizationType.AUTH_NONE),
    )


class TestGapRecordCreation(unittest.TestCase):
    """test_gap_record_creation: write 4 records, write_gap(5,10,CRASH), write more."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.chain_path = os.path.join(self.tmpdir, "test_gap.ahp")

    def test_gap_record_creation(self) -> None:
        writer = ChainWriter(self.chain_path)

        # Write 4 normal records (seq 1..4)
        for i in range(4):
            writer.write_record(_action(f"tool_{i}"))
        self.assertEqual(writer.sequence, 4)

        # Gap: records 5..10 were lost, gap record gets seq=11
        gap_rec = writer.write_gap(5, 10, GapReason.CRASH, "disk failure")
        self.assertEqual(gap_rec.sequence, 11)
        self.assertEqual(gap_rec.record_type, RecordType.GAP)

        # Next record should be seq=12
        next_rec = writer.write_record(_action("after_gap"))
        self.assertEqual(next_rec.sequence, 12)

        # Verify chain passes
        result = verify_chain(self.chain_path)
        self.assertTrue(result.valid, f"Chain invalid: {result.error}")
        self.assertEqual(result.gaps, 1)
        self.assertEqual(result.records_checked, 6)  # 4 + gap + 1


class TestRecoveryThenGap(unittest.TestCase):
    """test_recovery_then_gap: write records, recovery, gap, continue."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.chain_path = os.path.join(self.tmpdir, "test_recovery.ahp")

    def test_recovery_then_gap(self) -> None:
        writer = ChainWriter(self.chain_path)

        # Write 3 normal records (seq 1..3)
        for i in range(3):
            writer.write_record(_action(f"tool_{i}"))

        # Recovery record at seq=4
        recovery_rec = writer.write_recovery(
            records_verified=3,
            records_truncated=0,
            last_valid_seq=3,
            method=RecoveryMethod.CHAIN_SCAN,
            detail="recovered after crash",
        )
        self.assertEqual(recovery_rec.sequence, 4)
        self.assertEqual(recovery_rec.record_type, RecordType.RECOVERY)

        # Gap record: records 5..7 lost, gap record at seq=8
        gap_rec = writer.write_gap(5, 7, GapReason.CRASH)
        self.assertEqual(gap_rec.sequence, 8)
        self.assertEqual(gap_rec.record_type, RecordType.GAP)

        # Continue writing (seq=9)
        cont_rec = writer.write_record(_action("after_gap"))
        self.assertEqual(cont_rec.sequence, 9)

        # Verify chain passes
        result = verify_chain(self.chain_path)
        self.assertTrue(result.valid, f"Chain invalid: {result.error}")
        self.assertEqual(result.gaps, 1)


class TestCheckpoint(unittest.TestCase):
    """test_checkpoint: write 5 records then checkpoint."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.chain_path = os.path.join(self.tmpdir, "test_checkpoint.ahp")

    def test_checkpoint(self) -> None:
        writer = ChainWriter(self.chain_path)

        # Write 5 normal records (seq 1..5)
        for i in range(5):
            writer.write_record(_action(f"tool_{i}"))

        # Checkpoint at seq=6
        cp_rec = writer.write_checkpoint()
        self.assertEqual(cp_rec.sequence, 6)
        self.assertEqual(cp_rec.record_type, RecordType.CHECKPOINT)

        # Parse checkpoint payload to verify record_count=6
        reader = ChainReader(self.chain_path)
        all_bytes = reader.read_all()
        self.assertEqual(len(all_bytes), 6)

        env = parse_envelope(all_bytes[5])
        cp_data = parse_checkpoint_payload(env['payload_bytes'])
        self.assertEqual(cp_data['record_count'], 6)
        self.assertEqual(cp_data['gap_count'], 0)

        # Chain should still verify
        result = verify_chain(self.chain_path)
        self.assertTrue(result.valid, f"Chain invalid: {result.error}")


class TestGapConstraintValidation(unittest.TestCase):
    """test_gap_constraint_validation: bad GapRecord should fail verification."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.chain_path = os.path.join(self.tmpdir, "test_bad_gap.ahp")

    def test_gap_constraint_validation(self) -> None:
        writer = ChainWriter(self.chain_path)

        # Write 2 normal records (seq 1..2)
        for i in range(2):
            writer.write_record(_action(f"tool_{i}"))

        # Manually create a bad gap record with wrong count
        # Gap says records 3..5 lost (should be count=3) but we set count=99
        bad_payload = GapPayload(
            first_lost_sequence=3,
            last_lost_sequence=5,
            count=99,  # deliberately wrong
            reason=GapReason.CRASH,
            detail="",
        )
        # Override sequence to make it seq=6 (last_lost + 1)
        with writer._lock:
            writer._sequence = 5  # will be incremented to 6
            writer._write_record_unlocked(bad_payload)

        # verify_chain should fail due to first_lost_sequence mismatch
        # (the invalid count causes validation to fail, which generates a
        # different GapRecord with first_lost_sequence=6, causing mismatch)
        result = verify_chain(self.chain_path)
        self.assertFalse(result.valid)
        # The error is about first_lost_sequence because validation replaced the bad record
        self.assertIn("first_lost_sequence", result.error.lower())


class TestThreadSafety(unittest.TestCase):
    """test_thread_safety: 10 threads each writing 10 records."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.chain_path = os.path.join(self.tmpdir, "test_threaded.ahp")

    def test_thread_safety(self) -> None:
        writer = ChainWriter(self.chain_path)
        num_threads = 10
        records_per_thread = 10
        errors = []  # type: list[str]

        def write_records(thread_id: int) -> None:
            try:
                for j in range(records_per_thread):
                    writer.write_record(_action(f"thread{thread_id}_tool{j}"))
            except Exception as e:
                errors.append(f"Thread {thread_id}: {e}")

        threads = []
        for t in range(num_threads):
            th = threading.Thread(target=write_records, args=(t,))
            threads.append(th)

        for th in threads:
            th.start()
        for th in threads:
            th.join()

        self.assertEqual(len(errors), 0, f"Thread errors: {errors}")

        # Should have exactly 100 records
        reader = ChainReader(self.chain_path)
        all_bytes = reader.read_all()
        self.assertEqual(len(all_bytes), num_threads * records_per_thread)

        # All sequence numbers 1..100 present
        sequences = set()
        for stored in all_bytes:
            env = parse_envelope(stored)
            sequences.add(env['sequence'])
        self.assertEqual(sequences, set(range(1, 101)))

        # verify_chain should pass
        result = verify_chain(self.chain_path)
        self.assertTrue(result.valid, f"Chain invalid: {result.error}")
        self.assertEqual(result.records_checked, 100)


class TestInterleavedSessions(unittest.TestCase):
    """test_interleaved_sessions: two session_ids alternating writes."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.chain_path = os.path.join(self.tmpdir, "test_sessions.ahp")

    def test_interleaved_sessions(self) -> None:
        from ahp.core.uuid7 import uuid7

        session_a = uuid7()
        session_b = uuid7()
        writer = ChainWriter(self.chain_path)

        # Alternate between sessions
        for i in range(10):
            sid = session_a if i % 2 == 0 else session_b
            writer.write_record(_action(f"tool_{i}"), session_id=sid)

        # Verify chain
        result = verify_chain(self.chain_path)
        self.assertTrue(result.valid, f"Chain invalid: {result.error}")
        self.assertEqual(result.records_checked, 10)

        # Both sessions present
        reader = ChainReader(self.chain_path)
        all_bytes = reader.read_all()
        sessions_seen = set()
        for stored in all_bytes:
            env = parse_envelope(stored)
            sessions_seen.add(env['session_id'])

        self.assertIn(session_a, sessions_seen)
        self.assertIn(session_b, sessions_seen)
        self.assertEqual(len(sessions_seen), 2)


class TestMultipleGaps(unittest.TestCase):
    """test_multiple_gaps: records -> gap -> more records -> gap -> more records."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.chain_path = os.path.join(self.tmpdir, "test_multi_gap.ahp")

    def test_multiple_gaps(self) -> None:
        writer = ChainWriter(self.chain_path)

        # Write 3 records (seq 1..3)
        for i in range(3):
            writer.write_record(_action(f"tool_{i}"))

        # Gap 1: records 4..6 lost -> gap record at seq=7
        gap1 = writer.write_gap(4, 6, GapReason.CRASH, "first gap")
        self.assertEqual(gap1.sequence, 7)

        # Write 2 more (seq 8..9)
        for i in range(2):
            writer.write_record(_action(f"tool_after_gap1_{i}"))
        self.assertEqual(writer.sequence, 9)

        # Gap 2: records 10..12 lost -> gap record at seq=13
        gap2 = writer.write_gap(10, 12, GapReason.DISK_FULL, "second gap")
        self.assertEqual(gap2.sequence, 13)

        # Write 2 more (seq 14..15)
        for i in range(2):
            writer.write_record(_action(f"tool_after_gap2_{i}"))
        self.assertEqual(writer.sequence, 15)

        # Verify chain passes with 2 gaps
        result = verify_chain(self.chain_path)
        self.assertTrue(result.valid, f"Chain invalid: {result.error}")
        self.assertEqual(result.gaps, 2)
        # 3 + gap1 + 2 + gap2 + 2 = 9 actual records in chain
        self.assertEqual(result.records_checked, 9)


if __name__ == '__main__':
    unittest.main()
