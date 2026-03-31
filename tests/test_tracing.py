"""Tests for Session/Span context managers."""

from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path

from ahp._globals import set_default_recorder
from ahp.core.chain import ChainReader, parse_action_payload, parse_envelope
from ahp.core.types import ZERO_UUID, ActionType, RecordType
from ahp.recorder import AHPRecorder
from ahp.tracing import get_current_span, session


class TestSessionSpan(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.chain_path = str(Path(self.tmpdir) / "test.ahp")
        self.recorder = AHPRecorder(agent_name="test", chain_path=self.chain_path)
        set_default_recorder(self.recorder)

    def tearDown(self):
        self.recorder.close()
        set_default_recorder(None)

    def _get_actions(self):
        actions = []
        for stored in ChainReader(self.chain_path).read_all():
            env = parse_envelope(stored)
            if env["record_type"] == RecordType.ACTION:
                p = parse_action_payload(env["payload_bytes"])
                p["_record_id"] = env["record_id"]
                actions.append(p)
        return actions

    def test_basic_session_span(self):
        with session("task") as s:
            with s.span("agent") as agent:
                agent.log_tool(tool_name="search", parameters=b'{"q": "test"}')

        actions = self._get_actions()
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["tool_name"], "search")
        self.assertEqual(actions[0]["action_type"], ActionType.TOOL_CALL)

    def test_nested_spans(self):
        with session("task") as s:
            with s.span("parent") as parent:
                parent.log_llm(tool_name="gpt-4o", model_id="gpt-4o")

                with parent.child_span("child") as child:
                    child.log_tool(tool_name="search")
                    child.log_tool(tool_name="fetch")

        actions = self._get_actions()
        self.assertEqual(len(actions), 3)

        # Parent's action has no parent (root)
        parent_action = actions[0]
        self.assertEqual(parent_action["tool_name"], "gpt-4o")
        self.assertEqual(parent_action["parent_action_id"], ZERO_UUID)

        # Child actions have parent's record_id as parent_action_id
        parent_record_id = parent_action["_record_id"]
        self.assertEqual(actions[1]["parent_action_id"], parent_record_id)
        self.assertEqual(actions[2]["parent_action_id"], parent_record_id)

    def test_deeply_nested(self):
        with session("deep") as s:
            with s.span("level1") as l1:
                l1.log_tool(tool_name="l1_action")

                with l1.child_span("level2") as l2:
                    l2.log_tool(tool_name="l2_action")

                    with l2.child_span("level3") as l3:
                        l3.log_tool(tool_name="l3_action")

        actions = self._get_actions()
        self.assertEqual(len(actions), 3)

        # l1 → root
        self.assertEqual(actions[0]["parent_action_id"], ZERO_UUID)
        # l2 → l1's record_id
        self.assertEqual(actions[1]["parent_action_id"], actions[0]["_record_id"])
        # l3 → l2's record_id
        self.assertEqual(actions[2]["parent_action_id"], actions[1]["_record_id"])

    def test_multiple_actions_same_span(self):
        """First action sets span's record_id; all children use it."""
        with session("task") as s:
            with s.span("agent") as agent:
                agent.log_llm(tool_name="llm_call", model_id="gpt-4o")
                agent.log_tool(tool_name="tool1")
                agent.log_tool(tool_name="tool2")

        actions = self._get_actions()
        self.assertEqual(len(actions), 3)
        # All in the same span, so all have the same parent (ZERO_UUID for root span)
        for a in actions:
            self.assertEqual(a["parent_action_id"], ZERO_UUID)

    def test_log_llm(self):
        with session("task") as s:
            with s.span("agent") as agent:
                agent.log_llm(
                    tool_name="gpt-4o",
                    model_id="gpt-4o-2024-08-06",
                    provider="openai",
                )

        actions = self._get_actions()
        self.assertEqual(actions[0]["action_type"], ActionType.INFERENCE)
        self.assertEqual(actions[0]["model_id"], "gpt-4o-2024-08-06")
        self.assertEqual(actions[0]["provider"], "openai")

    def test_explicit_recorder(self):
        tmpdir2 = tempfile.mkdtemp()
        chain2 = str(Path(tmpdir2) / "other.ahp")
        rec2 = AHPRecorder(agent_name="other", chain_path=chain2)

        with session("task", recorder=rec2) as s:
            with s.span("agent") as agent:
                agent.log_tool(tool_name="explicit")

        rec2.close()

        actions = []
        for stored in ChainReader(chain2).read_all():
            env = parse_envelope(stored)
            if env["record_type"] == RecordType.ACTION:
                actions.append(parse_action_payload(env["payload_bytes"]))
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["tool_name"], "explicit")

    def test_contextvars_span_tracking(self):
        """get_current_span() returns the active span."""
        self.assertIsNone(get_current_span())

        with session("task") as s:
            self.assertIsNone(get_current_span())  # session doesn't set span

            with s.span("outer") as outer:
                self.assertIs(get_current_span(), outer)

                with outer.child_span("inner") as inner:
                    self.assertIs(get_current_span(), inner)

                # After inner exits, restored to outer
                self.assertIs(get_current_span(), outer)

            # After outer exits, restored to None
            self.assertIsNone(get_current_span())


class TestFailOpen(unittest.TestCase):
    def test_no_recorder(self):
        set_default_recorder(None)

        with session("task") as s:
            with s.span("agent") as agent:
                result = agent.log_tool(tool_name="no_recorder")
                self.assertIsNone(result)

                result2 = agent.log_llm(tool_name="no_recorder")
                self.assertIsNone(result2)

    def test_broken_recorder(self):
        class BrokenRecorder:
            def safe_record(self, **kw):
                raise RuntimeError("broken")

        set_default_recorder(BrokenRecorder())

        with session("task") as s:
            with s.span("agent") as agent:
                result = agent.log_tool(tool_name="broken")
                self.assertIsNone(result)

        set_default_recorder(None)


class TestAsyncTracing(unittest.TestCase):
    def test_async_session_span(self):
        tmpdir = tempfile.mkdtemp()
        chain = str(Path(tmpdir) / "async.ahp")
        rec = AHPRecorder(agent_name="async", chain_path=chain)
        set_default_recorder(rec)

        async def run():
            async with session("async-task") as s:
                async with s.span("agent") as agent:
                    agent.log_tool(tool_name="async_tool")

                    async with agent.child_span("sub") as sub:
                        sub.log_tool(tool_name="sub_tool")

        asyncio.run(run())
        rec.close()

        actions = []
        for stored in ChainReader(chain).read_all():
            env = parse_envelope(stored)
            if env["record_type"] == RecordType.ACTION:
                p = parse_action_payload(env["payload_bytes"])
                p["_record_id"] = env["record_id"]
                actions.append(p)

        self.assertEqual(len(actions), 2)
        self.assertEqual(actions[0]["tool_name"], "async_tool")
        self.assertEqual(actions[1]["tool_name"], "sub_tool")
        self.assertEqual(actions[1]["parent_action_id"], actions[0]["_record_id"])

        set_default_recorder(None)


if __name__ == "__main__":
    unittest.main()
