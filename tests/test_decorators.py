"""Tests for decorator-based instrumentation (@trace_tool, @trace_llm, @trace_agent)."""

from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path

from ahp._globals import set_default_recorder
from ahp.core.chain import ChainReader, parse_action_payload, parse_envelope
from ahp.core.types import ActionType, Protocol, RecordType, ResultStatus
from ahp.decorators import trace_agent, trace_llm, trace_tool
from ahp.recorder import AHPRecorder


class TestTraceToolSync(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.chain_path = str(Path(self.tmpdir) / "test.ahp")
        self.recorder = AHPRecorder(agent_name="test", chain_path=self.chain_path)
        set_default_recorder(self.recorder)

    def tearDown(self):
        self.recorder.close()
        set_default_recorder(None)

    def _get_actions(self):
        """Read all ACTION records from the chain."""
        reader = ChainReader(self.chain_path)
        actions = []
        for stored in reader.read_all():
            env = parse_envelope(stored)
            if env["record_type"] == RecordType.ACTION:
                actions.append(parse_action_payload(env["payload_bytes"]))
        return actions

    def test_trace_tool_bare(self):
        @trace_tool
        def search(query: str) -> dict:
            return {"results": [query]}

        result = search("hello")
        self.assertEqual(result, {"results": ["hello"]})

        actions = self._get_actions()
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["tool_name"], "search")
        self.assertEqual(actions[0]["action_type"], ActionType.TOOL_CALL)
        self.assertEqual(actions[0]["result_status"], ResultStatus.SUCCESS)

    def test_trace_tool_with_name(self):
        @trace_tool(tool_name="custom_search", protocol=Protocol.MCP)
        def search(q: str) -> str:
            return "found"

        search("test")

        actions = self._get_actions()
        self.assertEqual(actions[0]["tool_name"], "custom_search")
        self.assertEqual(actions[0]["protocol"], Protocol.MCP)

    def test_trace_tool_explicit_recorder(self):
        """Explicit recorder overrides the default."""
        tmpdir2 = tempfile.mkdtemp()
        chain2 = str(Path(tmpdir2) / "other.ahp")
        rec2 = AHPRecorder(agent_name="other", chain_path=chain2)

        @trace_tool(recorder=rec2)
        def greet(name: str) -> str:
            return f"hi {name}"

        greet("world")
        rec2.close()

        # Should be in rec2's chain, not the default
        reader = ChainReader(chain2)
        records = reader.read_all()
        action_count = sum(1 for s in records if parse_envelope(s)["record_type"] == RecordType.ACTION)
        self.assertEqual(action_count, 1)

    def test_captures_timing(self):
        import time

        @trace_tool
        def slow_fn() -> str:
            time.sleep(0.05)
            return "done"

        slow_fn()

        actions = self._get_actions()
        self.assertGreaterEqual(actions[0]["response_time_ms"], 40)

    def test_captures_exception(self):
        @trace_tool
        def failing_fn() -> None:
            raise ValueError("boom")

        with self.assertRaises(ValueError):
            failing_fn()

        actions = self._get_actions()
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["result_status"], ResultStatus.ERROR)
        self.assertEqual(actions[0]["tool_name"], "failing_fn")

    def test_preserves_function_metadata(self):
        @trace_tool
        def documented_fn():
            """This is a docstring."""
            pass

        self.assertEqual(documented_fn.__name__, "documented_fn")
        self.assertEqual(documented_fn.__doc__, "This is a docstring.")


class TestTraceLlm(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.chain_path = str(Path(self.tmpdir) / "test.ahp")
        self.recorder = AHPRecorder(agent_name="test", chain_path=self.chain_path)
        set_default_recorder(self.recorder)

    def tearDown(self):
        self.recorder.close()
        set_default_recorder(None)

    def _get_actions(self):
        reader = ChainReader(self.chain_path)
        actions = []
        for stored in reader.read_all():
            env = parse_envelope(stored)
            if env["record_type"] == RecordType.ACTION:
                actions.append(parse_action_payload(env["payload_bytes"]))
        return actions

    def test_trace_llm_with_model(self):
        @trace_llm(model_id="gpt-4o", provider="openai")
        def call_llm(prompt: str) -> str:
            return "response"

        call_llm("hello")

        actions = self._get_actions()
        self.assertEqual(actions[0]["action_type"], ActionType.INFERENCE)
        self.assertEqual(actions[0]["model_id"], "gpt-4o")
        self.assertEqual(actions[0]["provider"], "openai")
        self.assertEqual(actions[0]["protocol"], Protocol.HTTP)

    def test_trace_llm_bare(self):
        @trace_llm
        def my_llm(prompt: str) -> str:
            return "answer"

        my_llm("question")

        actions = self._get_actions()
        self.assertEqual(actions[0]["tool_name"], "my_llm")
        self.assertEqual(actions[0]["action_type"], ActionType.INFERENCE)


class TestTraceAgent(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.chain_path = str(Path(self.tmpdir) / "test.ahp")
        self.recorder = AHPRecorder(agent_name="test", chain_path=self.chain_path)
        set_default_recorder(self.recorder)

    def tearDown(self):
        self.recorder.close()
        set_default_recorder(None)

    def _get_actions(self):
        reader = ChainReader(self.chain_path)
        actions = []
        for stored in reader.read_all():
            env = parse_envelope(stored)
            if env["record_type"] == RecordType.ACTION:
                actions.append(parse_action_payload(env["payload_bytes"]))
        return actions

    def test_trace_agent(self):
        @trace_agent
        def delegate(task: str) -> str:
            return "completed"

        delegate("research")

        actions = self._get_actions()
        self.assertEqual(actions[0]["action_type"], ActionType.DELEGATION)
        self.assertEqual(actions[0]["tool_name"], "delegate")


class TestAsyncDecorators(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.chain_path = str(Path(self.tmpdir) / "test.ahp")
        self.recorder = AHPRecorder(agent_name="test", chain_path=self.chain_path)
        set_default_recorder(self.recorder)

    def tearDown(self):
        self.recorder.close()
        set_default_recorder(None)

    def _get_actions(self):
        reader = ChainReader(self.chain_path)
        actions = []
        for stored in reader.read_all():
            env = parse_envelope(stored)
            if env["record_type"] == RecordType.ACTION:
                actions.append(parse_action_payload(env["payload_bytes"]))
        return actions

    def test_async_trace_tool(self):
        @trace_tool
        async def async_search(query: str) -> dict:
            return {"results": [query]}

        result = asyncio.run(async_search("hello"))
        self.assertEqual(result, {"results": ["hello"]})

        actions = self._get_actions()
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["tool_name"], "async_search")
        self.assertEqual(actions[0]["action_type"], ActionType.TOOL_CALL)

    def test_async_decorator_with_async_recorder(self):
        """AsyncAHPRecorder's async safe_record is properly awaited."""
        from ahp.async_recorder import AsyncAHPRecorder

        tmpdir = tempfile.mkdtemp()
        chain_path = str(Path(tmpdir) / "async_rec.ahp")

        async def run():
            async_rec = AsyncAHPRecorder(agent_name="async-test", chain_path=chain_path)

            @trace_tool(recorder=async_rec)
            async def async_with_async_rec(x: int) -> int:
                return x * 10

            await async_rec.start()
            result = await async_with_async_rec(7)
            await async_rec.close()
            return result

        result = asyncio.run(run())
        self.assertEqual(result, 70)

        # Verify record was written (not silently dropped)
        reader = ChainReader(chain_path)
        actions = []
        for stored in reader.read_all():
            env = parse_envelope(stored)
            if env["record_type"] == RecordType.ACTION:
                actions.append(parse_action_payload(env["payload_bytes"]))
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["tool_name"], "async_with_async_rec")

    def test_async_exception_propagates(self):
        @trace_tool
        async def async_fail() -> None:
            raise RuntimeError("async boom")

        with self.assertRaises(RuntimeError):
            asyncio.run(async_fail())

        actions = self._get_actions()
        self.assertEqual(actions[0]["result_status"], ResultStatus.ERROR)


class TestFailOpen(unittest.TestCase):
    def test_no_recorder_set(self):
        """Function runs fine when no default recorder is set."""
        set_default_recorder(None)

        @trace_tool
        def safe_fn() -> str:
            return "works"

        result = safe_fn()
        self.assertEqual(result, "works")

    def test_broken_recorder(self):
        """Function runs fine even if recorder is broken."""

        class BrokenRecorder:
            def safe_record(self, **kwargs):
                raise RuntimeError("recorder is broken")

        set_default_recorder(BrokenRecorder())

        @trace_tool
        def still_works() -> str:
            return "ok"

        result = still_works()
        self.assertEqual(result, "ok")

        set_default_recorder(None)


class TestSerialization(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.chain_path = str(Path(self.tmpdir) / "test.ahp")
        self.recorder = AHPRecorder(agent_name="test", chain_path=self.chain_path)
        set_default_recorder(self.recorder)

    def tearDown(self):
        self.recorder.close()
        set_default_recorder(None)

    def test_non_serializable_args(self):
        """Non-JSON-serializable args fall back to repr()."""

        class Custom:
            def __repr__(self):
                return "Custom()"

        @trace_tool
        def fn(obj: object) -> str:
            return "ok"

        result = fn(Custom())
        self.assertEqual(result, "ok")  # didn't crash

    def test_large_args_truncated(self):
        """Args larger than 64KB are truncated before recording."""
        from ahp.decorators import _serialize_args

        big_args = ("x" * 100_000,)
        serialized = _serialize_args(big_args, {})
        self.assertLessEqual(len(serialized), 65536)

    def test_large_result_truncated(self):
        from ahp.decorators import _serialize_result

        big = "y" * 100_000
        serialized = _serialize_result(big)
        self.assertLessEqual(len(serialized), 65536)


if __name__ == "__main__":
    unittest.main()
