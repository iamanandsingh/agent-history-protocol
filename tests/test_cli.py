"""Tests for CLI commands: ahp trace, ahp gaps."""

from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest

from ahp.core.chain import ChainWriter
from ahp.core.records import ActionPayload, Authorization, BootPayload
from ahp.core.types import ActionType, AuthorizationType, GapReason, Protocol, ResultStatus
from ahp.core.uuid7 import uuid7


class TestCLITraceWithRealData(unittest.TestCase):
    """Test ahp trace and ahp gaps with real chain data."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.chain_path = os.path.join(self.tmpdir, "cli_test.ahp")
        self.session_id = uuid7()

    def test_gaps_command_with_real_gaps(self):
        """Chain with GapRecords: ahp gaps output mentions CRASH and gap count."""
        from ahp.cli.main import cmd_gaps

        writer = ChainWriter(self.chain_path)
        writer.write_record(BootPayload(agent_name="gap-test"), session_id=self.session_id)
        for i in range(3):
            writer.write_record(
                ActionPayload(
                    tool_name=f"tool_{i}",
                    result_status=ResultStatus.SUCCESS,
                    protocol=Protocol.MCP,
                    action_type=ActionType.TOOL_CALL,
                    authorization=Authorization(type=AuthorizationType.AUTH_NONE),
                ),
                session_id=self.session_id,
            )

        writer.write_gap(5, 8, GapReason.CRASH, "test crash gap")
        writer.write_record(
            ActionPayload(
                tool_name="after_gap",
                result_status=ResultStatus.SUCCESS,
                protocol=Protocol.MCP,
                action_type=ActionType.TOOL_CALL,
                authorization=Authorization(type=AuthorizationType.AUTH_NONE),
            ),
            session_id=self.session_id,
        )
        writer.close()

        captured = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured
        try:
            cmd_gaps(chain=self.chain_path)
        finally:
            sys.stdout = old_stdout

        output = captured.getvalue()
        self.assertIn("CRASH", output)
        self.assertIn("1 gap", output)

    def test_trace_command_with_real_session(self):
        """Chain with causal links: ahp trace output shows INFERENCE and tool name."""
        from ahp.cli.main import cmd_trace
        from ahp.core.uuid7 import uuid7_to_str

        writer = ChainWriter(self.chain_path)
        session = uuid7()
        session_str = uuid7_to_str(session)

        inference = writer.write_record(
            ActionPayload(
                tool_name="anthropic.messages",
                result_status=ResultStatus.SUCCESS,
                protocol=Protocol.HTTP,
                action_type=ActionType.INFERENCE,
                model_id="claude-sonnet-4-6",
                authorization=Authorization(type=AuthorizationType.AUTH_NONE),
            ),
            session_id=session,
        )

        writer.write_record(
            ActionPayload(
                parent_action_id=inference.record_id,
                tool_name="search_docs",
                result_status=ResultStatus.SUCCESS,
                protocol=Protocol.MCP,
                action_type=ActionType.TOOL_CALL,
                authorization=Authorization(type=AuthorizationType.AUTH_NONE),
            ),
            session_id=session,
        )
        writer.close()

        captured = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured
        try:
            cmd_trace(session_str[:8], chain=self.chain_path)
        finally:
            sys.stdout = old_stdout

        output = captured.getvalue()
        self.assertIn("INFERENCE", output)
        self.assertIn("search_docs", output)


if __name__ == "__main__":
    unittest.main()
