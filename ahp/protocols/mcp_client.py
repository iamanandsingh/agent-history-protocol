"""Real MCP client with AHP interception.

Makes actual JSON-RPC HTTP calls to an MCP tool server.
AHP records the real HTTP request/response.
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Optional, Any, Dict
from urllib.request import urlopen, Request
from urllib.error import URLError

from ahp.core.types import ResultStatus, Protocol, ActionType, AuthorizationType
from ahp.core.records import ActionPayload, Authorization
from ahp.core.chain import ChainWriter
from ahp.core.uuid7 import uuid7


class MCPClient:
    """Calls MCP tools via JSON-RPC over HTTP. AHP intercepts every call."""

    def __init__(self, server_url: str, writer: ChainWriter,
                 session_id: Optional[bytes] = None,
                 parent_record_id: Optional[bytes] = None):
        self.server_url = server_url
        self.writer = writer
        self.session_id = session_id or uuid7()
        self.parent_record_id = parent_record_id
        self._req_id = 0

    def set_parent(self, record_id: bytes) -> None:
        self.parent_record_id = record_id

    def list_tools(self) -> list:
        """List available tools on the MCP server."""
        result = self._rpc_call("tools/list", {})
        return result.get("tools", []) if result else []

    def call_tool(self, name: str, arguments: dict,
                  authorization: Optional[Authorization] = None) -> Any:
        """Call a tool on the MCP server via JSON-RPC. Returns the result.

        This makes a REAL HTTP call. AHP records the REAL request and response.
        """
        self._req_id += 1

        # Build JSON-RPC request
        rpc_request = {
            "jsonrpc": "2.0",
            "id": self._req_id,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments,
            },
        }

        request_bytes = json.dumps(rpc_request).encode()

        # Make REAL HTTP call to MCP server
        start = time.time()
        response_bytes = b''
        status_code = 200
        success = True

        try:
            req = Request(self.server_url, data=request_bytes,
                         headers={"Content-Type": "application/json"})
            with urlopen(req, timeout=10) as resp:
                response_bytes = resp.read()
                status_code = resp.status
        except URLError as e:
            response_bytes = json.dumps({"error": str(e)}).encode()
            status_code = 500
            success = False
        except Exception as e:
            response_bytes = json.dumps({"error": str(e)}).encode()
            status_code = 500
            success = False

        duration_ms = int((time.time() - start) * 1000)

        # Parse JSON-RPC response
        tool_result = None
        try:
            rpc_response = json.loads(response_bytes)
            if "error" in rpc_response:
                success = False
                err = rpc_response["error"]
                if isinstance(err, dict):
                    tool_result = {"error": err.get("message", str(err))}
                else:
                    tool_result = {"error": str(err)}
            else:
                result_obj = rpc_response.get("result", {})
                if isinstance(result_obj, dict):
                    content = result_obj.get("content", [])
                    if content and isinstance(content, list):
                        text = content[0].get("text", "{}") if isinstance(content[0], dict) else str(content[0])
                        try:
                            tool_result = json.loads(text)
                        except (json.JSONDecodeError, TypeError):
                            tool_result = text
                    else:
                        tool_result = result_obj
                else:
                    tool_result = result_obj
        except (json.JSONDecodeError, KeyError, IndexError, TypeError):
            tool_result = {"raw": response_bytes.decode('utf-8', errors='replace')}

        # Record in AHP — this is a REAL MCP protocol call
        params_hash = hashlib.sha256(request_bytes).digest()[:16]
        result_hash = hashlib.sha256(response_bytes).digest()[:16]

        if success:
            result_status = ResultStatus.SUCCESS
        elif status_code == 408 or status_code == 504:
            result_status = ResultStatus.TIMEOUT
        else:
            result_status = ResultStatus.ERROR

        action = ActionPayload(
            tool_name=name,
            parameters_hash=params_hash,
            result_hash=result_hash,
            result_status=result_status,
            response_time_ms=duration_ms,
            protocol=Protocol.MCP,  # THIS IS NOW TRUTHFUL — real JSON-RPC call
            action_type=ActionType.TOOL_CALL,
            target_entity=self.server_url,
            authorization=authorization or Authorization(type=AuthorizationType.AUTH_NONE),
        )

        if self.parent_record_id:
            action.parent_action_id = self.parent_record_id

        self.writer.write_record(action, session_id=self.session_id)

        return tool_result

    def _rpc_call(self, method: str, params: dict) -> Optional[dict]:
        """Raw JSON-RPC call."""
        self._req_id += 1
        body = json.dumps({
            "jsonrpc": "2.0",
            "id": self._req_id,
            "method": method,
            "params": params,
        }).encode()

        try:
            req = Request(self.server_url, data=body,
                         headers={"Content-Type": "application/json"})
            with urlopen(req, timeout=10) as resp:
                return json.loads(resp.read()).get("result")
        except Exception:
            return None
