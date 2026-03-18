"""Real MCP package interceptor — wraps the actual `mcp` Python package.

If the `mcp` package is installed, this wraps ClientSession.call_tool()
to automatically record every tool call in AHP.

If `mcp` is not installed, falls back to our built-in JSON-RPC MCP client.

Usage:
    from ahp.interceptors.mcp_auto import patch_mcp_client

    patch_mcp_client(recorder)
    # Now any mcp.ClientSession.call_tool() is recorded automatically
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Optional, Any

from ahp.core.types import ResultStatus, Protocol, ActionType, AuthorizationType
from ahp.core.records import ActionPayload, Authorization

try:
    from mcp import ClientSession
    HAS_MCP = True
except ImportError:
    HAS_MCP = False

_original_call_tool = None
_recorder = None


def patch_mcp_client(recorder: Any) -> bool:
    """Monkey-patch mcp.ClientSession.call_tool to record in AHP.

    Returns True if mcp package is available and patched, False otherwise.
    """
    global _original_call_tool, _recorder

    if not HAS_MCP:
        return False

    if _original_call_tool is not None:
        return True  # Already patched

    _original_call_tool = ClientSession.call_tool
    _recorder = recorder

    async def _intercepted_call_tool(self: Any, name: str, arguments: Optional[dict] = None) -> Any:
        params_bytes = json.dumps(arguments or {}, sort_keys=True).encode()
        start = time.time()
        error = None
        result = None

        try:
            result = await _original_call_tool(self, name, arguments)
        except Exception as e:
            error = e
            duration_ms = int((time.time() - start) * 1000)
            _record_tool_call(name, params_bytes, str(e).encode(), duration_ms, False)
            raise

        duration_ms = int((time.time() - start) * 1000)

        # Extract result content
        result_bytes = b''
        if result and hasattr(result, 'content'):
            content_parts = []
            for part in result.content:
                if hasattr(part, 'text'):
                    content_parts.append(part.text)
            result_bytes = json.dumps(content_parts).encode()

        _record_tool_call(name, params_bytes, result_bytes, duration_ms, True)
        return result

    ClientSession.call_tool = _intercepted_call_tool
    return True


def unpatch_mcp_client() -> None:
    """Restore original mcp.ClientSession.call_tool."""
    global _original_call_tool, _recorder

    if _original_call_tool is not None and HAS_MCP:
        ClientSession.call_tool = _original_call_tool
        _original_call_tool = None
        _recorder = None


def _record_tool_call(name: str, params: bytes, result: bytes,
                      duration_ms: int, success: bool) -> None:
    """Record a tool call in AHP (fail-open)."""
    if _recorder is None:
        return
    try:
        _recorder.safe_record(
            tool_name=name,
            parameters=params,
            result=result,
            protocol=Protocol.MCP,
            action_type=ActionType.TOOL_CALL,
            response_time_ms=duration_ms,
        )
    except Exception:
        pass  # Fail-open
