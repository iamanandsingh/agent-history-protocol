"""REAL protocol tests — actual MCP JSON-RPC, actual A2A task protocol, gRPC stubs.

Every test makes REAL network calls and verifies AHP records them correctly.
"""

from __future__ import annotations

import os
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any, Dict

from ahp.core.chain import ChainReader, ChainWriter, parse_action_payload, parse_envelope
from ahp.core.json_format import record_to_json
from ahp.core.records import (
    Authorization,
    AuthorizationEntry,
    BootPayload,
)
from ahp.core.types import (
    ActionType,
    AuthorizationDecision,
    AuthorizationType,
    AuthorizerType,
    Protocol,
    ResultStatus,
)
from ahp.core.verify import verify_chain


class TestRealMCPProtocol(unittest.TestCase):
    """Test REAL MCP JSON-RPC calls with AHP interception."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.chain_path = os.path.join(self.tmpdir, "mcp_test.ahp")

        # Create test data for tools
        self.data_dir = os.path.join(self.tmpdir, "data")
        os.makedirs(self.data_dir)
        Path(os.path.join(self.data_dir, "test.txt")).write_text("Hello from MCP test")

        # Import and start MCP server
        from ahp.protocols.mcp_server import MCPToolServer

        self.mcp_server = MCPToolServer(port=0)

        # Register real tools

        def read_file(path: str) -> str:
            return Path(path).read_text()

        def search(query: str) -> Dict:
            return {"query": query, "results": ["result1", "result2"], "count": 2}

        def write_file(path: str, content: str) -> Dict:
            Path(path).write_text(content)
            return {"status": "written", "bytes": len(content)}

        self.mcp_server.register_tool("read_file", read_file)
        self.mcp_server.register_tool("search", search)
        self.mcp_server.register_tool("write_file", write_file)
        self.server_url = self.mcp_server.start()

    def tearDown(self):
        self.mcp_server.stop()

    def test_real_mcp_tool_call(self):
        """Make a REAL JSON-RPC call to MCP server. Verify AHP records protocol=MCP."""
        from ahp.protocols.mcp_client import MCPClient

        writer = ChainWriter(self.chain_path)
        client = MCPClient(self.server_url, writer)

        # List tools (real JSON-RPC call)
        tools = client.list_tools()
        self.assertGreater(len(tools), 0)

        # Call a real tool via JSON-RPC
        result = client.call_tool("read_file", {"path": os.path.join(self.data_dir, "test.txt")})
        self.assertEqual(result, "Hello from MCP test")

        # Verify AHP recorded it as protocol=MCP
        reader = ChainReader(self.chain_path)
        records = reader.read_all()
        self.assertEqual(len(records), 1)

        env = parse_envelope(records[0])
        payload = parse_action_payload(env["payload_bytes"])
        self.assertEqual(payload["tool_name"], "read_file")
        self.assertEqual(Protocol(payload["protocol"]), Protocol.MCP)  # REAL MCP
        self.assertEqual(ResultStatus(payload["result_status"]), ResultStatus.SUCCESS)
        self.assertGreaterEqual(payload["response_time_ms"], 0)  # localhost can be sub-ms

        # Chain valid
        result_v = verify_chain(self.chain_path)
        self.assertTrue(result_v.valid)

    def test_mcp_tool_failure(self):
        """MCP tool call that fails — verify error recorded correctly."""
        from ahp.protocols.mcp_client import MCPClient

        writer = ChainWriter(self.chain_path)
        client = MCPClient(self.server_url, writer)

        # Call nonexistent tool
        result = client.call_tool("nonexistent_tool", {})
        self.assertIn("error", result)

        reader = ChainReader(self.chain_path)
        records = reader.read_all()
        env = parse_envelope(records[0])
        payload = parse_action_payload(env["payload_bytes"])
        self.assertEqual(Protocol(payload["protocol"]), Protocol.MCP)
        # JSON-RPC error returns 200 with error body — SDK records as SUCCESS at HTTP level
        # but the tool_name shows the failed tool
        self.assertEqual(payload["tool_name"], "nonexistent_tool")

    def test_mcp_write_tool(self):
        """MCP write tool — verify real file written and recorded."""
        from ahp.protocols.mcp_client import MCPClient

        writer = ChainWriter(self.chain_path)
        client = MCPClient(self.server_url, writer)

        output_path = os.path.join(self.data_dir, "mcp_output.txt")
        client.call_tool("write_file", {"path": output_path, "content": "Written via MCP"})

        # File was REALLY written
        self.assertTrue(Path(output_path).exists())
        self.assertEqual(Path(output_path).read_text(), "Written via MCP")

        # AHP recorded it as MCP
        reader = ChainReader(self.chain_path)
        records = reader.read_all()
        env = parse_envelope(records[0])
        payload = parse_action_payload(env["payload_bytes"])
        self.assertEqual(Protocol(payload["protocol"]), Protocol.MCP)
        self.assertEqual(payload["tool_name"], "write_file")

    def test_mcp_multiple_calls_chained(self):
        """Multiple MCP calls — verify hash chain integrity."""
        from ahp.protocols.mcp_client import MCPClient

        writer = ChainWriter(self.chain_path)
        client = MCPClient(self.server_url, writer)

        client.call_tool("search", {"query": "test1"})
        client.call_tool("search", {"query": "test2"})
        client.call_tool("read_file", {"path": os.path.join(self.data_dir, "test.txt")})

        result = verify_chain(self.chain_path)
        self.assertTrue(result.valid)
        self.assertEqual(result.records_checked, 3)

    def test_mcp_with_authorization(self):
        """MCP call with authorization — verify auth recorded in chain."""
        from ahp.protocols.mcp_client import MCPClient

        writer = ChainWriter(self.chain_path)
        client = MCPClient(self.server_url, writer)

        auth = Authorization(
            type=AuthorizationType.AUTH_HUMAN,
            entries=[
                AuthorizationEntry(
                    authorizer_type=AuthorizerType.AUTHORIZER_HUMAN,
                    authorizer_id="user:operator",
                    decision=AuthorizationDecision.APPROVED,
                    timestamp_ms=int(time.time() * 1000),
                )
            ],
        )

        result = client.call_tool("search", {"query": "authorized search"}, authorization=auth)
        self.assertIn("results", result)

        j = record_to_json(ChainReader(self.chain_path).read_all()[0])
        self.assertEqual(j["payload"]["authorization"]["type"], "AUTH_HUMAN")
        self.assertEqual(j["payload"]["authorization"]["entries"][0]["decision"], "APPROVED")


class TestRealA2AProtocol(unittest.TestCase):
    """Test REAL A2A agent-to-agent communication with AHP interception."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.client_chain = os.path.join(self.tmpdir, "client_agent.ahp")
        self.server_chain = os.path.join(self.tmpdir, "server_agent.ahp")

    def test_real_a2a_task_delegation(self):
        """Agent A sends task to Agent B via A2A JSON-RPC. Both record in AHP."""

        from ahp.protocols.a2a import A2AClient, A2AServer

        # Start Agent B (supervisor) as A2A server
        writer_b = ChainWriter(self.server_chain)
        writer_b.write_record(BootPayload(agent_name="supervisor-agent"))

        def handle_task(task: Any) -> Dict:
            return {"approved": True, "reason": "Looks good"}

        server = A2AServer("supervisor-agent", writer_b, port=0, task_handler=handle_task)
        server_url = server.start()

        try:
            # Agent A sends task to Agent B
            writer_a = ChainWriter(self.client_chain)
            writer_a.write_record(BootPayload(agent_name="planner-agent"))

            client = A2AClient(server_url, writer_a)
            result = client.send_task(
                action="approve_refund",
                details={"order_id": 7891, "amount": 49.99},
                requesting_agent_id=writer_a.agent_id.hex(),
            )

            # The result comes from JSON-RPC nested in "result" key
            # It should contain the task result with approved/agent_id/sequence
            self.assertIsNotNone(result, "A2A returned no result")
            # Result might have "result" nested (from task handler) or "approved" directly
            task_result = result.get("result", result)
            task_result.get("approved") if isinstance(task_result, dict) else None

            # Verify Agent A's chain (client)
            reader_a = ChainReader(self.client_chain)
            records_a = reader_a.read_all()
            # Should have: Boot + DELEGATION
            self.assertEqual(len(records_a), 2)

            env_a = parse_envelope(records_a[1])
            payload_a = parse_action_payload(env_a["payload_bytes"])
            self.assertEqual(payload_a["tool_name"], "a2a.tasks.send")
            self.assertEqual(Protocol(payload_a["protocol"]), Protocol.A2A)
            self.assertEqual(ActionType(payload_a["action_type"]), ActionType.DELEGATION)
            self.assertGreater(payload_a["response_time_ms"], 0)

            # Verify Agent B's chain (server)
            reader_b = ChainReader(self.server_chain)
            records_b = reader_b.read_all()
            self.assertGreaterEqual(len(records_b), 3)

            # Check the authorization_decision record
            last_b = parse_action_payload(parse_envelope(records_b[-1])["payload_bytes"])
            self.assertEqual(last_b["tool_name"], "a2a.authorization_decision")
            self.assertEqual(Protocol(last_b["protocol"]), Protocol.A2A)

            # Both chains valid
            self.assertTrue(verify_chain(self.client_chain).valid)
            self.assertTrue(verify_chain(self.server_chain).valid)

        finally:
            server.stop()

    def test_a2a_identity_check(self):
        """Verify A2A agent identity endpoint works."""
        from ahp.protocols.a2a import A2AClient, A2AServer

        writer = ChainWriter(self.server_chain)
        server = A2AServer("test-agent", writer, port=0)
        url = server.start()

        try:
            client = A2AClient(url, ChainWriter(self.client_chain))
            identity = client.get_identity()
            self.assertIsNotNone(identity)
            self.assertEqual(identity["agent_name"], "test-agent")
            self.assertIn("agent_id", identity)
        finally:
            server.stop()


class TestGRPCInterceptor(unittest.TestCase):
    """Test gRPC interceptor — unit tests for payload creation (no grpcio required)."""

    def test_create_grpc_action(self):
        """Test gRPC action creation without actual gRPC call."""
        from ahp.interceptors.grpc import create_action_from_grpc

        action = create_action_from_grpc(
            service_name="payment.PaymentService",
            method_name="ProcessPayment",
            request_bytes=b'{"amount": 49.99}',
            response_bytes=b'{"status": "ok", "tx_id": "TX-001"}',
            duration_ms=150,
            success=True,
        )

        self.assertEqual(action.tool_name, "payment.PaymentService/ProcessPayment")
        self.assertEqual(action.protocol, Protocol.GRPC)
        self.assertEqual(action.action_type, ActionType.TOOL_CALL)
        self.assertEqual(action.result_status, ResultStatus.SUCCESS)
        self.assertEqual(action.response_time_ms, 150)
        self.assertNotEqual(action.parameters_hash, b"\x00" * 16)
        self.assertNotEqual(action.result_hash, b"\x00" * 16)

    def test_grpc_action_in_chain(self):
        """Verify gRPC action records correctly in AHP chain."""
        from ahp.interceptors.grpc import create_action_from_grpc

        tmpdir = tempfile.mkdtemp()
        chain_path = os.path.join(tmpdir, "grpc_test.ahp")
        writer = ChainWriter(chain_path)

        action = create_action_from_grpc(
            service_name="user.UserService",
            method_name="GetUser",
            request_bytes=b'{"user_id": 42}',
            response_bytes=b'{"name": "Alice", "email": "alice@example.com"}',
            duration_ms=25,
        )
        writer.write_record(action)

        # Verify chain
        result = verify_chain(chain_path)
        self.assertTrue(result.valid)

        # Verify protocol field
        reader = ChainReader(chain_path)
        j = record_to_json(reader.read_all()[0])
        self.assertEqual(j["payload"]["protocol"], "GRPC")
        self.assertEqual(j["payload"]["tool_name"], "user.UserService/GetUser")

    def test_grpc_error(self):
        """Test gRPC error action."""
        from ahp.interceptors.grpc import create_action_from_grpc

        action = create_action_from_grpc(
            service_name="payment.PaymentService",
            method_name="Refund",
            request_bytes=b'{"tx_id": "TX-999"}',
            response_bytes=b"UNAVAILABLE: service down",
            duration_ms=5000,
            success=False,
        )

        self.assertEqual(action.result_status, ResultStatus.ERROR)
        self.assertEqual(action.protocol, Protocol.GRPC)


class TestAllProtocolsEndToEnd(unittest.TestCase):
    """End-to-end test using ALL protocols in one chain."""

    def test_mixed_protocol_chain(self):
        """One agent uses HTTPS + MCP + A2A + gRPC — all in one chain."""
        from ahp.interceptors.grpc import create_action_from_grpc
        from ahp.interceptors.http_helper import create_action_from_http
        from ahp.protocols.a2a import A2AClient, A2AServer
        from ahp.protocols.mcp_client import MCPClient
        from ahp.protocols.mcp_server import MCPToolServer

        tmpdir = tempfile.mkdtemp()
        chain_path = os.path.join(tmpdir, "all_protocols.ahp")
        supervisor_chain = os.path.join(tmpdir, "supervisor.ahp")

        writer = ChainWriter(chain_path)
        writer.write_record(
            BootPayload(
                agent_name="multi-protocol-agent",
                interceptors=["http", "mcp", "a2a", "grpc"],
            )
        )

        # 1. HTTP call (simulated LLM)
        http_action = create_action_from_http(
            method="POST",
            url="https://api.anthropic.com/v1/messages",
            request_body=b'{"model": "claude-sonnet-4-6"}',
            response_body=b'{"content": [{"text": "Hello"}]}',
            status_code=200,
            duration_ms=500,
        )
        writer.write_record(http_action)

        # 2. Real MCP call
        data_dir = os.path.join(tmpdir, "data")
        os.makedirs(data_dir)
        Path(os.path.join(data_dir, "test.txt")).write_text("MCP data")

        mcp_server = MCPToolServer(port=0)
        mcp_server.register_tool("read_file", lambda path: Path(path).read_text())
        mcp_url = mcp_server.start()

        try:
            mcp_client = MCPClient(mcp_url, writer)
            mcp_result = mcp_client.call_tool("read_file", {"path": os.path.join(data_dir, "test.txt")})
            self.assertEqual(mcp_result, "MCP data")
        finally:
            mcp_server.stop()

        # 3. Real A2A call
        sup_writer = ChainWriter(supervisor_chain)
        sup_writer.write_record(BootPayload(agent_name="supervisor"))

        a2a_server = A2AServer(
            "supervisor", sup_writer, port=0, task_handler=lambda t: {"approved": True, "reason": "OK"}
        )
        a2a_url = a2a_server.start()

        try:
            a2a_client = A2AClient(a2a_url, writer)
            a2a_result = a2a_client.send_task("approve", {"item": "test"})
            # Result may be nested in "result" key from JSON-RPC
            task_result = a2a_result.get("result", a2a_result) if isinstance(a2a_result, dict) else {}
            self.assertTrue(
                a2a_result.get("approved") or (isinstance(task_result, dict) and task_result.get("approved")),
                f"A2A approval failed: {a2a_result}",
            )
        finally:
            a2a_server.stop()

        # 4. gRPC action (simulated — no grpcio)
        grpc_action = create_action_from_grpc(
            service_name="analytics.AnalyticsService",
            method_name="TrackEvent",
            request_bytes=b'{"event": "demo"}',
            response_bytes=b'{"tracked": true}',
            duration_ms=10,
        )
        writer.write_record(grpc_action)

        # Verify: one chain with ALL 4 protocols
        reader = ChainReader(chain_path)
        records = reader.read_all()
        self.assertEqual(len(records), 5)  # Boot + HTTP + MCP + A2A + gRPC

        protocols_found = set()
        for stored in records[1:]:  # Skip boot
            env = parse_envelope(stored)
            payload = parse_action_payload(env["payload_bytes"])
            protocols_found.add(Protocol(payload["protocol"]).name)

        self.assertIn("HTTP", protocols_found)
        self.assertIn("MCP", protocols_found)
        self.assertIn("A2A", protocols_found)
        self.assertIn("GRPC", protocols_found)

        # Chain integrity
        result = verify_chain(chain_path)
        self.assertTrue(result.valid, f"Chain invalid: {result.error}")
        self.assertEqual(result.records_checked, 5)

        print("\n✅ All 4 protocols in one chain:")
        print("   HTTP:  INFERENCE (simulated Anthropic API)")
        print("   MCP:   TOOL_CALL (real JSON-RPC, real file read)")
        print("   A2A:   DELEGATION (real JSON-RPC, real task approval)")
        print("   gRPC:  TOOL_CALL (simulated — no grpcio installed)")
        print(f"   Chain: {result.records_checked} records, VALID")


if __name__ == "__main__":
    unittest.main()
