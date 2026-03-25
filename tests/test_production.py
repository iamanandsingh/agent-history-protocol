"""Production readiness tests — sustained load, backpressure, validation, fsync."""

from __future__ import annotations

import asyncio
import os
import tempfile
import threading
import time
import unittest

from ahp.core.async_chain import AsyncChainWriter
from ahp.core.chain import ChainWriter
from ahp.core.records import (
    ActionPayload,
    Authorization,
    AuthorizationEntry,
    Record,
)
from ahp.core.types import (
    SCHEMA_VERSION,
    ZERO_HASH_32,
    ActionType,
    AuthorizationType,
    AuthorizerType,
    Protocol,
    RecordType,
    ResultStatus,
)
from ahp.core.uuid7 import uuid7
from ahp.core.validation import validate_record
from ahp.core.verify import verify_chain


def _payload(i: int) -> ActionPayload:
    return ActionPayload(
        tool_name=f"tool_{i}",
        result_status=ResultStatus.SUCCESS,
        protocol=Protocol.MCP,
        action_type=ActionType.TOOL_CALL,
        authorization=Authorization(type=AuthorizationType.AUTH_NONE),
    )


class TestSustainedLoad(unittest.TestCase):
    """Simulate sustained production traffic."""

    def test_sync_10k_records(self):
        """Write 10K records synchronously — must complete and verify."""
        tmpdir = tempfile.mkdtemp()
        path = os.path.join(tmpdir, "load.ahp")
        writer = ChainWriter(path, fsync_mode="none")

        start = time.time()
        for i in range(10000):
            writer.write_record(_payload(i))
        elapsed = time.time() - start
        writer.close()

        result = verify_chain(path)
        self.assertTrue(result.valid)
        self.assertEqual(result.records_checked, 10000)
        # Should complete in reasonable time
        self.assertLess(elapsed, 30.0, f"10K records took {elapsed:.1f}s — too slow")

    def test_async_10k_records(self):
        """Write 10K records asynchronously — must complete and verify."""
        tmpdir = tempfile.mkdtemp()
        path = os.path.join(tmpdir, "async_load.ahp")

        async def _run():
            writer = AsyncChainWriter(path)
            await writer.start()
            start = time.time()
            for i in range(10000):
                await writer.write_record(_payload(i))
            await writer.stop()
            return time.time() - start

        elapsed = asyncio.run(_run())

        result = verify_chain(path)
        self.assertTrue(result.valid)
        self.assertEqual(result.records_checked, 10000)
        self.assertLess(elapsed, 30.0)

    def test_concurrent_threads_100k(self):
        """100 threads x 100 records = 10K total. Chain must be valid."""
        tmpdir = tempfile.mkdtemp()
        path = os.path.join(tmpdir, "thread_load.ahp")
        writer = ChainWriter(path, fsync_mode="none")

        errors = []

        def write_batch(thread_id: int):
            try:
                for i in range(100):
                    writer.write_record(_payload(thread_id * 100 + i))
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=write_batch, args=(t,)) for t in range(100)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        writer.close()

        self.assertEqual(len(errors), 0, f"Thread errors: {errors}")

        result = verify_chain(path)
        self.assertTrue(result.valid)
        self.assertEqual(result.records_checked, 10000)

    def test_async_concurrent_tasks(self):
        """50 async tasks x 100 records = 5K total. Chain must be valid."""
        tmpdir = tempfile.mkdtemp()
        path = os.path.join(tmpdir, "async_concurrent.ahp")

        async def _run():
            writer = AsyncChainWriter(path)
            await writer.start()

            async def batch(task_id: int):
                for i in range(100):
                    await writer.write_record(_payload(task_id * 100 + i))

            await asyncio.gather(*[batch(t) for t in range(50)])
            await writer.stop()

        asyncio.run(_run())

        result = verify_chain(path)
        self.assertTrue(result.valid)
        self.assertEqual(result.records_checked, 5000)


class TestFsync(unittest.TestCase):
    """Test fsync modes."""

    def test_fsync_every(self):
        tmpdir = tempfile.mkdtemp()
        path = os.path.join(tmpdir, "fsync_every.ahp")
        writer = ChainWriter(path, fsync_mode="every")
        for i in range(5):
            writer.write_record(_payload(i))
        writer.close()

        result = verify_chain(path)
        self.assertTrue(result.valid)
        self.assertEqual(result.records_checked, 5)

    def test_fsync_batch(self):
        tmpdir = tempfile.mkdtemp()
        path = os.path.join(tmpdir, "fsync_batch.ahp")
        writer = ChainWriter(path, fsync_mode="batch")
        for i in range(200):  # > 100 to trigger batch fsync
            writer.write_record(_payload(i))
        writer.close()

        result = verify_chain(path)
        self.assertTrue(result.valid)
        self.assertEqual(result.records_checked, 200)

    def test_fsync_none(self):
        tmpdir = tempfile.mkdtemp()
        path = os.path.join(tmpdir, "fsync_none.ahp")
        writer = ChainWriter(path, fsync_mode="none")
        for i in range(10):
            writer.write_record(_payload(i))
        writer.close()

        result = verify_chain(path)
        self.assertTrue(result.valid)


class TestInputValidation(unittest.TestCase):
    """Test input validation and security hardening."""

    def test_valid_record(self):
        record = Record(
            record_id=uuid7(),
            agent_id=uuid7(),
            session_id=uuid7(),
            timestamp_ms=int(time.time() * 1000),
            sequence=1,
            prev_hash=ZERO_HASH_32,
            schema_version=SCHEMA_VERSION,
            record_type=RecordType.ACTION,
            payload=_payload(0),
        )
        errors = validate_record(record)
        self.assertEqual(len(errors), 0)

    def test_invalid_record_id_length(self):
        record = Record(
            record_id=b"\x01" * 8,  # Wrong length
            agent_id=uuid7(),
            session_id=uuid7(),
            timestamp_ms=1,
            sequence=1,
            prev_hash=ZERO_HASH_32,
            schema_version=1,
            record_type=RecordType.ACTION,
            payload=_payload(0),
        )
        errors = validate_record(record)
        self.assertGreater(len(errors), 0)

    def test_tool_name_too_long(self):
        payload = ActionPayload(
            tool_name="x" * 2000,  # > MAX_TOOL_NAME_LENGTH
            result_status=ResultStatus.SUCCESS,
            protocol=Protocol.MCP,
            action_type=ActionType.TOOL_CALL,
            authorization=Authorization(type=AuthorizationType.AUTH_NONE),
        )
        record = Record(
            record_id=uuid7(),
            agent_id=uuid7(),
            session_id=uuid7(),
            timestamp_ms=1,
            sequence=1,
            prev_hash=ZERO_HASH_32,
            schema_version=1,
            record_type=RecordType.ACTION,
            payload=payload,
        )
        errors = validate_record(record)
        self.assertGreater(len(errors), 0)
        self.assertTrue(any("tool_name" in e for e in errors))

    def test_auth_none_with_entries(self):
        payload = ActionPayload(
            tool_name="test",
            result_status=ResultStatus.SUCCESS,
            protocol=Protocol.MCP,
            action_type=ActionType.TOOL_CALL,
            authorization=Authorization(
                type=AuthorizationType.AUTH_NONE,
                entries=[
                    AuthorizationEntry(
                        authorizer_type=AuthorizerType.AUTHORIZER_HUMAN,
                        authorizer_id="user:test",
                    )
                ],
            ),
        )
        record = Record(
            record_id=uuid7(),
            agent_id=uuid7(),
            session_id=uuid7(),
            timestamp_ms=1,
            sequence=1,
            prev_hash=ZERO_HASH_32,
            schema_version=1,
            record_type=RecordType.ACTION,
            payload=payload,
        )
        errors = validate_record(record)
        self.assertTrue(any("AUTH_NONE must have 0 entries" in e for e in errors))

    def test_multi_party_needs_2_entries(self):
        payload = ActionPayload(
            tool_name="test",
            result_status=ResultStatus.SUCCESS,
            protocol=Protocol.MCP,
            action_type=ActionType.TOOL_CALL,
            authorization=Authorization(
                type=AuthorizationType.AUTH_MULTI_PARTY,
                entries=[
                    AuthorizationEntry(
                        authorizer_type=AuthorizerType.AUTHORIZER_HUMAN,
                        authorizer_id="user:test",
                    )
                ],
            ),
        )
        record = Record(
            record_id=uuid7(),
            agent_id=uuid7(),
            session_id=uuid7(),
            timestamp_ms=1,
            sequence=1,
            prev_hash=ZERO_HASH_32,
            schema_version=1,
            record_type=RecordType.ACTION,
            payload=payload,
        )
        errors = validate_record(record)
        self.assertTrue(any("MULTI_PARTY" in e for e in errors))

    def test_agent_authorizer_needs_agent_id(self):
        payload = ActionPayload(
            tool_name="test",
            result_status=ResultStatus.SUCCESS,
            protocol=Protocol.MCP,
            action_type=ActionType.TOOL_CALL,
            authorization=Authorization(
                type=AuthorizationType.AUTH_AGENT,
                entries=[
                    AuthorizationEntry(
                        authorizer_type=AuthorizerType.AUTHORIZER_AGENT,
                        authorizer_id="supervisor",
                        # authorizer_agent_id is zero bytes — should fail
                    )
                ],
            ),
        )
        record = Record(
            record_id=uuid7(),
            agent_id=uuid7(),
            session_id=uuid7(),
            timestamp_ms=1,
            sequence=1,
            prev_hash=ZERO_HASH_32,
            schema_version=1,
            record_type=RecordType.ACTION,
            payload=payload,
        )
        errors = validate_record(record)
        self.assertTrue(any("authorizer_agent_id" in e for e in errors))

    def test_gap_count_mismatch(self):
        from ahp.core.records import GapPayload

        payload = GapPayload(first_lost_sequence=5, last_lost_sequence=10, count=99)
        record = Record(
            record_id=uuid7(),
            agent_id=uuid7(),
            session_id=uuid7(),
            timestamp_ms=1,
            sequence=11,
            prev_hash=ZERO_HASH_32,
            schema_version=1,
            record_type=RecordType.GAP,
            payload=payload,
        )
        errors = validate_record(record)
        self.assertTrue(any("count mismatch" in e for e in errors))


class TestBackpressure(unittest.TestCase):
    """Test async queue backpressure behavior."""

    def test_queue_limit(self):
        """Verify AsyncChainWriter respects max_queue."""
        tmpdir = tempfile.mkdtemp()
        path = os.path.join(tmpdir, "bp.ahp")

        async def _run():
            # Small queue to test backpressure
            writer = AsyncChainWriter(path, max_queue=10)
            await writer.start()

            # Write more than queue size — should not crash
            for i in range(50):
                await writer.write_record(_payload(i))

            await writer.stop()
            return writer.record_count

        count = asyncio.run(_run())
        self.assertEqual(count, 50)

        result = verify_chain(path)
        self.assertTrue(result.valid)


if __name__ == "__main__":
    unittest.main()
