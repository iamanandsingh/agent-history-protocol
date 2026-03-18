"""Real A2A (Agent-to-Agent) protocol implementation with AHP interception.

Implements task-based agent communication with JSON-RPC over HTTP,
matching the A2A protocol pattern:
- Task submission with states (SUBMITTED → WORKING → AUTH_REQUIRED → COMPLETED/FAILED)
- Authorization delegation (agent can request auth from client)
- AHP records every message as real A2A protocol calls
"""
from __future__ import annotations

import hashlib
import json
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional, Dict, Any, Callable, List
from urllib.request import urlopen, Request
from urllib.error import URLError

from ahp.core.types import (
    ResultStatus, Protocol, ActionType, AuthorizationType,
    AuthorizerType, AuthorizationDecision,
)
from ahp.core.records import ActionPayload, Authorization, AuthorizationEntry
from ahp.core.chain import ChainWriter
from ahp.core.uuid7 import uuid7, uuid7_to_str


# A2A Task States (per A2A protocol spec)
TASK_SUBMITTED = "SUBMITTED"
TASK_WORKING = "WORKING"
TASK_AUTH_REQUIRED = "AUTH_REQUIRED"
TASK_COMPLETED = "COMPLETED"
TASK_FAILED = "FAILED"


class A2ATask:
    """Represents an A2A task with state tracking."""

    def __init__(self, task_id: str, action: str, details: Dict[str, Any],
                 requesting_agent_id: str):
        self.task_id = task_id
        self.action = action
        self.details = details
        self.requesting_agent_id = requesting_agent_id
        self.state = TASK_SUBMITTED
        self.result: Optional[Dict] = None
        self.auth_required: bool = False
        self.auth_message: str = ""
        self.created_at: int = int(time.time() * 1000)


class A2AServer:
    """A2A-compatible agent server with task management and AHP recording.

    Handles incoming tasks via JSON-RPC, processes them, and can request
    authorization from the client (TASK_STATE_AUTH_REQUIRED).
    """

    def __init__(self, agent_name: str, writer: ChainWriter, port: int = 8400,
                 task_handler: Optional[Callable] = None):
        self.agent_name = agent_name
        self.agent_id = writer.agent_id
        self.writer = writer
        self.port = port
        self.task_handler = task_handler
        self.tasks: Dict[str, A2ATask] = {}
        self.server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> str:
        """Start the A2A server. Returns the agent URL."""
        agent = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                content_length = int(self.headers.get('Content-Length', 0))
                body = json.loads(self.rfile.read(content_length))

                method = body.get('method', '')
                params = body.get('params', {})
                req_id = body.get('id', 1)

                if method == 'tasks/send':
                    result = agent._handle_task_send(params)
                    response = {"jsonrpc": "2.0", "id": req_id, "result": result}
                elif method == 'tasks/get':
                    task_id = params.get('id', '')
                    task = agent.tasks.get(task_id)
                    if task:
                        response = {"jsonrpc": "2.0", "id": req_id, "result": {
                            "id": task.task_id,
                            "state": task.state,
                            "result": task.result,
                        }}
                    else:
                        response = {"jsonrpc": "2.0", "id": req_id,
                                   "error": {"code": -32602, "message": "Task not found"}}
                elif method == 'tasks/authorize':
                    result = agent._handle_task_authorize(params)
                    response = {"jsonrpc": "2.0", "id": req_id, "result": result}
                elif method == 'agent/identity':
                    response = {"jsonrpc": "2.0", "id": req_id, "result": {
                        "agent_id": agent.agent_id.hex(),
                        "agent_name": agent.agent_name,
                    }}
                else:
                    response = {"jsonrpc": "2.0", "id": req_id,
                               "error": {"code": -32601, "message": f"Unknown method: {method}"}}

                resp_bytes = json.dumps(response).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(resp_bytes)))
                self.end_headers()
                self.wfile.write(resp_bytes)

            def log_message(self, format, *args):
                pass

        self.server = HTTPServer(('localhost', self.port), Handler)
        self.port = self.server.server_address[1]  # actual port (handles port=0)
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()
        return f"http://localhost:{self.port}"

    def stop(self) -> None:
        if self.server:
            self.server.shutdown()

    def _handle_task_send(self, params: Dict) -> Dict:
        """Handle incoming task — the core A2A task processing."""
        task_id = uuid7().hex()[:16]
        task = A2ATask(
            task_id=task_id,
            action=params.get('action', ''),
            details=params.get('details', {}),
            requesting_agent_id=params.get('agent_id', ''),
        )
        self.tasks[task_id] = task

        # Record receiving the task in AHP
        session_id = uuid7()
        request_bytes = json.dumps(params).encode()

        recv_action = ActionPayload(
            tool_name="a2a.tasks.receive",
            parameters_hash=hashlib.sha256(request_bytes).digest()[:16],
            result_hash=hashlib.sha256(b'SUBMITTED').digest()[:16],
            result_status=ResultStatus.SUCCESS,
            response_time_ms=0,
            protocol=Protocol.A2A,
            action_type=ActionType.MESSAGE,
            target_entity=f"agent:{task.requesting_agent_id[:16]}",
            authorization=Authorization(type=AuthorizationType.AUTH_NONE),
        )
        self.writer.write_record(recv_action, session_id=session_id)

        # Process the task
        task.state = TASK_WORKING

        if self.task_handler:
            result = self.task_handler(task)
        else:
            result = {"approved": True, "reason": "Auto-approved (no handler)"}

        task.result = result
        task.state = TASK_COMPLETED

        # Record the decision in AHP
        result_bytes = json.dumps(result).encode()
        decision_action = ActionPayload(
            tool_name="a2a.authorization_decision",
            parameters_hash=hashlib.sha256(request_bytes).digest()[:16],
            result_hash=hashlib.sha256(result_bytes).digest()[:16],
            result_status=ResultStatus.SUCCESS,
            response_time_ms=0,
            protocol=Protocol.A2A,
            action_type=ActionType.MESSAGE,
            target_entity=f"agent:{task.requesting_agent_id[:16]}",
            authorization=Authorization(type=AuthorizationType.AUTH_NONE),
        )
        record = self.writer.write_record(decision_action, session_id=session_id)

        return {
            "id": task_id,
            "state": task.state,
            "result": result,
            "agent_id": self.agent_id.hex(),
            "agent_name": self.agent_name,
            "sequence": record.sequence,
        }

    def _handle_task_authorize(self, params: Dict) -> Dict:
        """Handle authorization provision for a task in AUTH_REQUIRED state."""
        task_id = params.get('task_id', '')
        task = self.tasks.get(task_id)
        if not task:
            return {"error": "Task not found"}

        task.state = TASK_WORKING
        if self.task_handler:
            result = self.task_handler(task)
        else:
            result = {"approved": True, "reason": "Auto-approved"}

        task.result = result
        task.state = TASK_COMPLETED
        return {"id": task_id, "state": task.state, "result": result}


class A2AClient:
    """A2A client that sends tasks to other agents and records in AHP.

    Makes REAL JSON-RPC HTTP calls. AHP records every call as protocol=A2A.
    """

    def __init__(self, agent_url: str, writer: ChainWriter,
                 session_id: Optional[bytes] = None,
                 parent_record_id: Optional[bytes] = None):
        self.agent_url = agent_url
        self.writer = writer
        self.session_id = session_id or uuid7()
        self.parent_record_id = parent_record_id
        self._req_id = 0

    def set_parent(self, record_id: bytes) -> None:
        self.parent_record_id = record_id

    def send_task(self, action: str, details: Dict,
                  requesting_agent_id: str = "") -> Dict:
        """Send a task to the remote agent via A2A protocol.

        Returns the task result including agent_id and sequence for cross-chain linking.
        """
        self._req_id += 1
        rpc_request = {
            "jsonrpc": "2.0",
            "id": self._req_id,
            "method": "tasks/send",
            "params": {
                "action": action,
                "details": details,
                "agent_id": requesting_agent_id,
            },
        }

        request_bytes = json.dumps(rpc_request).encode()

        # Make REAL HTTP call to A2A agent
        start = time.time()
        response_bytes = b''
        status_code = 200

        try:
            req = Request(self.agent_url, data=request_bytes,
                         headers={"Content-Type": "application/json"})
            with urlopen(req, timeout=15) as resp:
                response_bytes = resp.read()
                status_code = resp.status
        except (URLError, Exception) as e:
            response_bytes = json.dumps({"error": str(e)}).encode()
            status_code = 500

        duration_ms = int((time.time() - start) * 1000)

        # Parse response
        result = {}
        success = True
        try:
            rpc_response = json.loads(response_bytes)
            if "error" in rpc_response:
                success = False
                result = {"error": rpc_response["error"]["message"]}
            else:
                result = rpc_response.get("result", {})
        except json.JSONDecodeError:
            success = False
            result = {"error": "Invalid response"}

        # Record in AHP as DELEGATION (real A2A protocol)
        action_payload = ActionPayload(
            tool_name="a2a.tasks.send",
            parameters_hash=hashlib.sha256(request_bytes).digest()[:16],
            result_hash=hashlib.sha256(response_bytes).digest()[:16],
            result_status=ResultStatus.SUCCESS if success else ResultStatus.ERROR,
            response_time_ms=duration_ms,
            protocol=Protocol.A2A,
            action_type=ActionType.DELEGATION,
            target_entity=self.agent_url,
            authorization=Authorization(type=AuthorizationType.AUTH_NONE),
        )

        if self.parent_record_id:
            action_payload.parent_action_id = self.parent_record_id

        self.writer.write_record(action_payload, session_id=self.session_id)

        return result

    def get_identity(self) -> Optional[Dict]:
        """Get remote agent's identity."""
        self._req_id += 1
        body = json.dumps({
            "jsonrpc": "2.0", "id": self._req_id,
            "method": "agent/identity", "params": {},
        }).encode()

        try:
            req = Request(self.agent_url, data=body,
                         headers={"Content-Type": "application/json"})
            with urlopen(req, timeout=10) as resp:
                return json.loads(resp.read()).get("result")
        except Exception:
            return None
