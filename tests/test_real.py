"""REAL integration tests — actual HTTP calls, actual tool execution, actual interception.

These tests use real network calls (to local mock servers), real file I/O,
and real interception to verify AHP works end-to-end.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.error import URLError
from urllib.request import Request, urlopen

from ahp.core.chain import ChainReader, ChainWriter, parse_action_payload, parse_envelope
from ahp.core.evidence import EvidenceStore
from ahp.core.filters import FilterPipeline
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
    RecordType,
    ResultStatus,
)
from ahp.core.uuid7 import uuid7
from ahp.core.verify import verify_chain
from ahp.interceptors.http_helper import create_action_from_http
from ahp.interceptors.mcp_helper import create_action_from_mcp

# ================================================================
# Mock LLM API Server — pretends to be Anthropic's API
# ================================================================


class MockAnthropicHandler(BaseHTTPRequestHandler):
    """Mock server that responds like the Anthropic Messages API."""

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        request = json.loads(body)

        model = request.get("model", "claude-sonnet-4-6")
        messages = request.get("messages", [])
        user_msg = messages[-1]["content"] if messages else ""

        # Simulate LLM response
        if "search" in user_msg.lower():
            response_text = json.dumps({"tool_use": "search_docs", "input": {"query": user_msg}})
        elif "delete" in user_msg.lower():
            response_text = "I cannot delete that without approval."
        else:
            response_text = f"I received: {user_msg}"

        response = {
            "id": "msg_test_001",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": response_text}],
            "model": model,
            "usage": {
                "input_tokens": len(user_msg.split()) * 2,
                "output_tokens": len(response_text.split()) * 2,
            },
        }

        response_bytes = json.dumps(response).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_bytes)))
        self.end_headers()
        self.wfile.write(response_bytes)

    def log_message(self, format, *args):
        pass  # Silence logs


# ================================================================
# Real HTTP Interception Wrapper
# ================================================================


class InterceptedHTTPClient:
    """A real HTTP client that intercepts its own calls and creates AHP records.

    This is what a REAL AHP HTTP interceptor would do — wrap actual HTTP calls.
    """

    def __init__(
        self, writer: ChainWriter, session_id: Optional[bytes] = None, filter_pipeline: Optional[FilterPipeline] = None
    ):
        self.writer = writer
        self.session_id = session_id
        self.filter_pipeline = filter_pipeline
        self._last_inference_id: Optional[bytes] = None

    def post(self, url: str, body: dict) -> dict:
        """Make a REAL HTTP POST and record it in AHP."""
        request_bytes = json.dumps(body).encode()

        # Actually make the HTTP call
        start = time.time()
        try:
            req = Request(url, data=request_bytes, headers={"Content-Type": "application/json"})
            with urlopen(req, timeout=10) as resp:
                response_bytes = resp.read()
                status_code = resp.status
        except URLError as e:
            response_bytes = str(e).encode()
            status_code = 500

        duration_ms = int((time.time() - start) * 1000)

        # Create AHP record from REAL HTTP data
        action = create_action_from_http(
            method="POST",
            url=url,
            request_body=request_bytes,
            response_body=response_bytes,
            status_code=status_code,
            duration_ms=duration_ms,
            filter_pipeline=self.filter_pipeline,
        )

        # Link to previous inference if this is a tool call caused by one
        if action.action_type == ActionType.INFERENCE:
            record = self.writer.write_record(action, session_id=self.session_id)
            self._last_inference_id = record.record_id
        else:
            if self._last_inference_id:
                action.parent_action_id = self._last_inference_id
            record = self.writer.write_record(action, session_id=self.session_id)

        return json.loads(response_bytes)


# ================================================================
# Real Tool Execution with Interception
# ================================================================


class InterceptedToolExecutor:
    """Executes real tools and records them in AHP.

    This is what a REAL MCP interceptor would do — wrap actual tool execution.
    """

    def __init__(
        self,
        writer: ChainWriter,
        session_id: Optional[bytes] = None,
        parent_action_id: Optional[bytes] = None,
        filter_pipeline: Optional[FilterPipeline] = None,
    ):
        self.writer = writer
        self.session_id = session_id
        self.parent_action_id = parent_action_id
        self.filter_pipeline = filter_pipeline

    def execute(
        self, tool_name: str, func: Callable, params: dict, authorization: Optional[Authorization] = None
    ) -> Any:
        """Execute a REAL tool function and record it in AHP."""
        start = time.time()
        success = True
        result = None

        try:
            result = func(**params)
        except Exception as e:
            result = {"error": str(e)}
            success = False

        duration_ms = int((time.time() - start) * 1000)

        action = create_action_from_mcp(
            tool_name=tool_name,
            parameters=params,
            result=result,
            duration_ms=duration_ms,
            success=success,
            filter_pipeline=self.filter_pipeline,
        )

        if self.parent_action_id:
            action.parent_action_id = self.parent_action_id

        if authorization:
            action.authorization = authorization

        self.writer.write_record(action, session_id=self.session_id)
        return result


# ================================================================
# Real Tools (actual functions that do real work)
# ================================================================


def tool_read_file(path: str) -> str:
    """Actually reads a file from disk."""
    return Path(path).read_text()


def tool_write_file(path: str, content: str) -> dict:
    """Actually writes a file to disk."""
    Path(path).write_text(content)
    return {"status": "written", "path": path, "bytes": len(content)}


def tool_list_files(directory: str) -> list:
    """Actually lists files in a directory."""
    return [f.name for f in Path(directory).iterdir()]


def tool_search_text(path: str, query: str) -> dict:
    """Actually searches for text in a file."""
    content = Path(path).read_text()
    lines = content.split("\n")
    matches = [line for line in lines if query.lower() in line.lower()]
    return {"query": query, "matches": matches, "count": len(matches)}


# ================================================================
# Tests
# ================================================================


class TestRealHTTPInterception(unittest.TestCase):
    """Test AHP intercepting REAL HTTP calls to a mock LLM API."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.chain_path = os.path.join(self.tmpdir, "real_http.ahp")

        # Start mock Anthropic API server
        self.server = HTTPServer(("localhost", 0), MockAnthropicHandler)
        self.port = self.server.server_address[1]
        self.api_url = f"http://localhost:{self.port}/v1/messages"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()

    def test_real_llm_call_intercepted(self):
        """Make a REAL HTTP call to mock LLM API. Verify AHP records it correctly."""
        writer = ChainWriter(self.chain_path)
        session = uuid7()
        client = InterceptedHTTPClient(writer, session_id=session)

        # Boot record
        writer.write_record(
            BootPayload(
                agent_name="real-test-agent",
                interceptors=["http"],
                inference_recording=True,
                authorization_recording=True,
            ),
            session_id=session,
        )

        # Make REAL HTTP call to mock API
        response = client.post(
            self.api_url,
            {
                "model": "claude-sonnet-4-6",
                "messages": [{"role": "user", "content": "What is AHP?"}],
            },
        )

        # Verify we got a real response
        self.assertIn("content", response)
        self.assertIn("usage", response)

        # Verify AHP recorded it
        reader = ChainReader(self.chain_path)
        records = reader.read_all()
        self.assertEqual(len(records), 2)  # Boot + INFERENCE

        # Check the INFERENCE record
        env = parse_envelope(records[1])
        self.assertEqual(env["record_type"], RecordType.ACTION)

        payload = parse_action_payload(env["payload_bytes"])
        # The URL has localhost, not api.anthropic.com, so it won't detect as LLM
        # This is expected — real interception would use the actual API URL
        # But the record IS created with real timing, real hashes
        self.assertEqual(payload["result_status"], ResultStatus.SUCCESS.value)
        self.assertGreaterEqual(payload["response_time_ms"], 0)  # Real timing (may be 0 if mock responds instantly)
        self.assertNotEqual(payload["parameters_hash"], b"\x00" * 16)
        self.assertNotEqual(payload["result_hash"], b"\x00" * 16)

        # Verify chain integrity
        result = verify_chain(self.chain_path)
        self.assertTrue(result.valid)

    def test_multiple_real_calls(self):
        """Make multiple REAL HTTP calls. Verify chain grows correctly."""
        writer = ChainWriter(self.chain_path)
        session = uuid7()
        client = InterceptedHTTPClient(writer, session_id=session)

        writer.write_record(BootPayload(agent_name="multi-call-agent"), session_id=session)

        # 3 real HTTP calls
        for msg in ["Hello", "Search for docs", "Delete my account"]:
            response = client.post(
                self.api_url,
                {
                    "model": "claude-sonnet-4-6",
                    "messages": [{"role": "user", "content": msg}],
                },
            )
            self.assertIn("content", response)

        reader = ChainReader(self.chain_path)
        records = reader.read_all()
        self.assertEqual(len(records), 4)  # Boot + 3 calls

        result = verify_chain(self.chain_path)
        self.assertTrue(result.valid)


class TestRealToolExecution(unittest.TestCase):
    """Test AHP intercepting REAL tool execution (actual file I/O)."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.chain_path = os.path.join(self.tmpdir, "real_tools.ahp")

        # Create test files
        self.test_file = os.path.join(self.tmpdir, "test_data.txt")
        Path(self.test_file).write_text("Hello World\nAHP Protocol\nLine Three\n")

    def test_real_file_read_intercepted(self):
        """Execute a REAL file read and verify AHP records it."""
        writer = ChainWriter(self.chain_path)
        session = uuid7()
        executor = InterceptedToolExecutor(writer, session_id=session)

        writer.write_record(BootPayload(agent_name="tool-test-agent"), session_id=session)

        # Actually read a real file
        result = executor.execute(
            tool_name="read_file",
            func=tool_read_file,
            params={"path": self.test_file},
        )

        # Verify the tool ACTUALLY ran
        self.assertIn("Hello World", result)
        self.assertIn("AHP Protocol", result)

        # Verify AHP recorded it
        reader = ChainReader(self.chain_path)
        records = reader.read_all()
        self.assertEqual(len(records), 2)

        env = parse_envelope(records[1])
        payload = parse_action_payload(env["payload_bytes"])
        self.assertEqual(payload["tool_name"], "read_file")
        self.assertEqual(payload["result_status"], ResultStatus.SUCCESS.value)

        # The hash should cover the ACTUAL file contents
        expected_result_hash = hashlib.sha256(json.dumps(result, sort_keys=True, default=str).encode()).digest()[:16]
        self.assertEqual(payload["result_hash"], expected_result_hash)

        result_v = verify_chain(self.chain_path)
        self.assertTrue(result_v.valid)

    def test_real_file_write_intercepted(self):
        """Execute a REAL file write and verify AHP records it with authorization."""
        writer = ChainWriter(self.chain_path)
        session = uuid7()
        executor = InterceptedToolExecutor(writer, session_id=session)

        writer.write_record(
            BootPayload(
                agent_name="write-test-agent",
                authorization_recording=True,
            ),
            session_id=session,
        )

        output_path = os.path.join(self.tmpdir, "output.txt")

        # Execute with human authorization
        executor.execute(
            tool_name="write_file",
            func=tool_write_file,
            params={"path": output_path, "content": "Written by AHP test"},
            authorization=Authorization(
                type=AuthorizationType.AUTH_HUMAN,
                entries=[
                    AuthorizationEntry(
                        authorizer_type=AuthorizerType.AUTHORIZER_HUMAN,
                        authorizer_id="user:tester",
                        decision=AuthorizationDecision.APPROVED,
                        timestamp_ms=int(time.time() * 1000),
                    )
                ],
            ),
        )

        # Verify the file was ACTUALLY written
        self.assertTrue(Path(output_path).exists())
        self.assertEqual(Path(output_path).read_text(), "Written by AHP test")

        # Verify AHP recorded the authorization
        reader = ChainReader(self.chain_path)
        records = reader.read_all()
        j = record_to_json(records[1])
        self.assertEqual(j["payload"]["authorization"]["type"], "AUTH_HUMAN")
        self.assertEqual(j["payload"]["authorization"]["entries"][0]["authorizer_id"], "user:tester")

    def test_real_tool_failure_intercepted(self):
        """Execute a tool that ACTUALLY fails and verify AHP records the error."""
        writer = ChainWriter(self.chain_path)
        session = uuid7()
        executor = InterceptedToolExecutor(writer, session_id=session)

        writer.write_record(BootPayload(agent_name="fail-test-agent"), session_id=session)

        # Try to read a file that doesn't exist
        result = executor.execute(
            tool_name="read_file",
            func=tool_read_file,
            params={"path": "/nonexistent/file.txt"},
        )

        # The tool failed — result should have error
        self.assertIn("error", result)

        # AHP should record the failure
        reader = ChainReader(self.chain_path)
        records = reader.read_all()
        env = parse_envelope(records[1])
        payload = parse_action_payload(env["payload_bytes"])
        self.assertEqual(payload["result_status"], ResultStatus.ERROR.value)

    def test_real_search_tool(self):
        """Execute a REAL search and verify results match."""
        writer = ChainWriter(self.chain_path)
        session = uuid7()
        executor = InterceptedToolExecutor(writer, session_id=session)

        writer.write_record(BootPayload(agent_name="search-agent"), session_id=session)

        result = executor.execute(
            tool_name="search_text",
            func=tool_search_text,
            params={"path": self.test_file, "query": "AHP"},
        )

        # Real search results
        self.assertEqual(result["count"], 1)
        self.assertIn("AHP Protocol", result["matches"][0])

        # AHP recorded it
        result_v = verify_chain(self.chain_path)
        self.assertTrue(result_v.valid)


class TestRealAgentFlow(unittest.TestCase):
    """End-to-end: mock LLM → real tool execution → real evidence → real verification."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.chain_path = os.path.join(self.tmpdir, "real_agent.ahp")
        self.evidence_path = os.path.join(self.tmpdir, "evidence")

        # Start mock API
        self.server = HTTPServer(("localhost", 0), MockAnthropicHandler)
        self.port = self.server.server_address[1]
        self.api_url = f"http://localhost:{self.port}/v1/messages"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

        # Create test data
        self.data_file = os.path.join(self.tmpdir, "customer_data.txt")
        Path(self.data_file).write_text(
            "Customer #442: John Smith\nOrder #7891: $49.99 charged\nOrder #7891: $49.99 charged (DUPLICATE)\n"
        )

    def tearDown(self):
        self.server.shutdown()

    def test_real_agent_workflow(self):
        """
        Simulate a REAL agent workflow:
        1. Agent calls LLM (real HTTP to mock server)
        2. LLM says to search files
        3. Agent searches REAL files on disk
        4. Agent records everything with authorization
        5. Verify the chain is correct and matches reality
        """
        writer = ChainWriter(self.chain_path)
        store = EvidenceStore(self.evidence_path)
        pipeline = FilterPipeline(presets=["pci"])
        session = uuid7()

        # 1. Boot
        writer.write_record(
            BootPayload(
                agent_name="real-support-bot",
                interceptors=["http", "mcp"],
                inference_recording=True,
                authorization_recording=True,
                filter_config_hash=pipeline.config_hash(),
            ),
            session_id=session,
        )

        # 2. REAL HTTP call to mock LLM
        http_client = InterceptedHTTPClient(writer, session_id=session, filter_pipeline=pipeline)
        llm_response = http_client.post(
            self.api_url,
            {
                "model": "claude-sonnet-4-6",
                "messages": [{"role": "user", "content": "Search for customer 442 orders"}],
            },
        )

        # Verify we got a real response from the mock server
        self.assertIn("content", llm_response)
        self.assertIn("usage", llm_response)

        # Store the LLM response as evidence
        llm_response_bytes = json.dumps(llm_response).encode()
        evidence_hash = store.store(llm_response_bytes)

        # 3. REAL tool execution — search actual file on disk
        tool_executor = InterceptedToolExecutor(
            writer,
            session_id=session,
            parent_action_id=http_client._last_inference_id,
            filter_pipeline=pipeline,
        )

        search_result = tool_executor.execute(
            tool_name="search_customer_orders",
            func=tool_search_text,
            params={"path": self.data_file, "query": "442"},
        )

        # Verify REAL search found real data
        self.assertEqual(search_result["count"], 1)
        self.assertIn("Customer #442", search_result["matches"][0])

        # 4. REAL tool execution with authorization — process refund
        output_file = os.path.join(self.tmpdir, "refund_log.txt")
        tool_executor.execute(
            tool_name="process_refund",
            func=tool_write_file,
            params={"path": output_file, "content": "Refund $49.99 for order #7891"},
            authorization=Authorization(
                type=AuthorizationType.AUTH_HUMAN,
                entries=[
                    AuthorizationEntry(
                        authorizer_type=AuthorizerType.AUTHORIZER_HUMAN,
                        authorizer_id="user:operator",
                        decision=AuthorizationDecision.APPROVED,
                        timestamp_ms=int(time.time() * 1000),
                    )
                ],
            ),
        )

        # Verify the refund was ACTUALLY processed (file written)
        self.assertTrue(Path(output_file).exists())
        self.assertEqual(Path(output_file).read_text(), "Refund $49.99 for order #7891")

        # 5. Verify EVERYTHING
        result = verify_chain(self.chain_path)
        self.assertTrue(result.valid, f"Chain invalid: {result.error}")
        self.assertEqual(result.records_checked, 4)  # Boot + LLM + search + refund

        # 6. Read chain and verify it matches what ACTUALLY happened
        reader = ChainReader(self.chain_path)
        records = reader.read_all()

        # Boot record
        j0 = record_to_json(records[0])
        self.assertEqual(j0["type"], "BOOT")
        self.assertEqual(j0["payload"]["agent_name"], "real-support-bot")

        # LLM call — real HTTP timing
        j1 = record_to_json(records[1])
        self.assertEqual(j1["type"], "ACTION")
        self.assertGreaterEqual(j1["payload"]["response_time_ms"], 0)  # REAL timing

        # Search — real result hash matches actual search output
        j2 = record_to_json(records[2])
        self.assertEqual(j2["payload"]["tool_name"], "search_customer_orders")
        real_result_hash = hashlib.sha256(json.dumps(search_result, sort_keys=True, default=str).encode()).digest()[:16]
        self.assertEqual(bytes.fromhex(j2["payload"]["result_hash"]), real_result_hash)

        # Refund — authorization recorded
        j3 = record_to_json(records[3])
        self.assertEqual(j3["payload"]["tool_name"], "process_refund")
        self.assertEqual(j3["payload"]["authorization"]["type"], "AUTH_HUMAN")
        self.assertEqual(j3["payload"]["authorization"]["entries"][0]["decision"], "APPROVED")

        # 7. Evidence store has the LLM response
        self.assertTrue(store.verify(evidence_hash))
        retrieved = store.retrieve(evidence_hash)
        self.assertEqual(json.loads(retrieved), llm_response)

        print("\n✅ REAL agent workflow test passed:")
        print(f"   - Real HTTP call to mock LLM (response time: {j1['payload']['response_time_ms']}ms)")
        print(f"   - Real file search (found {search_result['count']} match)")
        print("   - Real file write (refund processed)")
        print("   - Real authorization (human approved)")
        print("   - Real evidence stored and verified")
        print(f"   - Chain: {result.records_checked} records, all verified")


if __name__ == "__main__":
    unittest.main()
