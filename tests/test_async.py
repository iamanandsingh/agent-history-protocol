"""Async tests — AsyncChainWriter + AsyncAHPRecorder."""

from __future__ import annotations

import asyncio
import os
import tempfile
import unittest

from ahp.async_recorder import AsyncAHPRecorder
from ahp.core.async_chain import AsyncChainWriter
from ahp.core.chain import ChainReader, parse_envelope
from ahp.core.json_format import record_to_json
from ahp.core.records import (
    ActionPayload,
    Authorization,
)
from ahp.core.types import (
    ActionType,
    AuthorizationType,
    Protocol,
    RecordType,
    ResultStatus,
)
from ahp.core.verify import verify_chain


def run_async(coro):
    """Helper to run async test in sync unittest."""
    return asyncio.run(coro)


class TestAsyncChainWriter(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.chain_path = os.path.join(self.tmpdir, "async_test.ahp")

    def test_basic_write(self):
        async def _test():
            writer = AsyncChainWriter(self.chain_path)
            await writer.start()

            for i in range(5):
                await writer.write_record(
                    ActionPayload(
                        tool_name=f"tool_{i}",
                        result_status=ResultStatus.SUCCESS,
                        protocol=Protocol.MCP,
                        action_type=ActionType.TOOL_CALL,
                        authorization=Authorization(type=AuthorizationType.AUTH_NONE),
                    )
                )

            await writer.stop()

            # Verify chain
            result = verify_chain(self.chain_path)
            self.assertTrue(result.valid)
            self.assertEqual(result.records_checked, 5)

        run_async(_test())

    def test_concurrent_writes(self):
        async def _test():
            writer = AsyncChainWriter(self.chain_path)
            await writer.start()

            async def write_batch(start: int, count: int):
                for i in range(count):
                    await writer.write_record(
                        ActionPayload(
                            tool_name=f"tool_{start}_{i}",
                            result_status=ResultStatus.SUCCESS,
                            protocol=Protocol.MCP,
                            action_type=ActionType.TOOL_CALL,
                            authorization=Authorization(type=AuthorizationType.AUTH_NONE),
                        )
                    )

            # 5 concurrent tasks writing 10 records each
            tasks = [write_batch(i * 10, 10) for i in range(5)]
            await asyncio.gather(*tasks)
            await writer.stop()

            # All 50 records should be in the chain
            reader = ChainReader(self.chain_path)
            records = reader.read_all()
            self.assertEqual(len(records), 50)

            result = verify_chain(self.chain_path)
            self.assertTrue(result.valid)

        run_async(_test())

    def test_sequence_ordering(self):
        async def _test():
            writer = AsyncChainWriter(self.chain_path)
            await writer.start()

            records = []
            for i in range(10):
                r = await writer.write_record(
                    ActionPayload(
                        tool_name=f"tool_{i}",
                        result_status=ResultStatus.SUCCESS,
                        protocol=Protocol.MCP,
                        action_type=ActionType.TOOL_CALL,
                        authorization=Authorization(type=AuthorizationType.AUTH_NONE),
                    )
                )
                records.append(r)

            await writer.stop()

            # Sequences should be 1-10 in order
            for i, r in enumerate(records):
                self.assertEqual(r.sequence, i + 1)

        run_async(_test())


class TestAsyncRecorder(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.chain_path = os.path.join(self.tmpdir, "async_recorder.ahp")

    def test_basic_recording(self):
        async def _test():
            recorder = AsyncAHPRecorder(
                agent_name="async-test",
                chain_path=self.chain_path,
                level=1,
            )
            await recorder.start()

            await recorder.record_action(
                tool_name="search",
                parameters=b'{"query": "test"}',
                result=b'{"results": []}',
                protocol=Protocol.MCP,
            )
            await recorder.record_action(
                tool_name="read_file",
                parameters=b'{"path": "/tmp/test"}',
                result=b"file contents",
            )

            await recorder.stop()

            result = verify_chain(self.chain_path)
            self.assertTrue(result.valid)
            # Boot + 2 actions = 3 (no KeyGenesis at level 1)
            self.assertEqual(result.records_checked, 3)

        run_async(_test())

    def test_inference_recording(self):
        async def _test():
            recorder = AsyncAHPRecorder(
                agent_name="async-inference",
                chain_path=self.chain_path,
                level=1,
            )
            await recorder.start()

            await recorder.record_inference(
                tool_name="anthropic.messages",
                parameters=b'{"model": "claude"}',
                result=b'{"text": "hello"}',
                model_id="claude-sonnet-4-6",
                input_token_count=100,
                output_token_count=50,
                response_time_ms=850,
            )

            await recorder.stop()

            reader = ChainReader(self.chain_path)
            records = reader.read_all()
            # Boot + inference
            self.assertEqual(len(records), 2)

            j = record_to_json(records[1])
            self.assertEqual(j["payload"]["action_type"], "INFERENCE")
            self.assertEqual(j["payload"]["model_id"], "claude-sonnet-4-6")
            self.assertEqual(j["payload"]["input_token_count"], 100)

        run_async(_test())

    def test_fail_open(self):
        async def _test():
            recorder = AsyncAHPRecorder(
                agent_name="async-failopen",
                chain_path=self.chain_path,
                level=1,
            )
            await recorder.start()

            # Normal record
            await recorder.record_action(tool_name="good_call", parameters=b"ok", result=b"ok")

            # Force a failure by passing bad data to safe_record
            original_write = recorder.writer.write_record

            async def broken_write(*a, **kw):
                raise RuntimeError("Simulated failure")

            recorder.writer.write_record = broken_write
            result = await recorder.safe_record(tool_name="bad_call")
            self.assertIsNone(result)  # Failed but didn't crash

            # Restore and record again
            recorder.writer.write_record = original_write
            recorder._pending_gap = False  # Skip gap emission for simplicity
            await recorder.record_action(tool_name="after_fail", parameters=b"ok", result=b"ok")

            await recorder.stop()

            # Chain should have records (Boot + good_call + after_fail)
            reader = ChainReader(self.chain_path)
            records = reader.read_all()
            self.assertGreaterEqual(len(records), 3)

        run_async(_test())

    def test_auto_checkpoint(self):
        async def _test():
            recorder = AsyncAHPRecorder(
                agent_name="async-checkpoint",
                chain_path=self.chain_path,
                level=1,
                checkpoint_interval=5,
            )
            await recorder.start()

            for i in range(7):
                await recorder.record_action(
                    tool_name=f"tool_{i}",
                    parameters=b"params",
                    result=b"result",
                )

            await recorder.stop()

            # Should have: Boot + 5 actions + checkpoint + 2 actions = 9
            reader = ChainReader(self.chain_path)
            records = reader.read_all()
            has_checkpoint = any(parse_envelope(s)["record_type"] == RecordType.CHECKPOINT for s in records)
            self.assertTrue(has_checkpoint)

        run_async(_test())

    def test_level2_signing(self):
        async def _test():
            recorder = AsyncAHPRecorder(
                agent_name="async-signed",
                chain_path=self.chain_path,
                level=2,
                checkpoint_interval=3,
            )
            await recorder.start()

            for i in range(4):
                await recorder.record_action(
                    tool_name=f"tool_{i}",
                    parameters=b"p",
                    result=b"r",
                )

            await recorder.stop()

            # Should have KeyGenesisRecord
            reader = ChainReader(self.chain_path)
            records = reader.read_all()
            has_key = any(parse_envelope(s)["record_type"] == RecordType.KEY for s in records)
            self.assertTrue(has_key)

        run_async(_test())


if __name__ == "__main__":
    unittest.main()
