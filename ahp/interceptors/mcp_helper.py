"""MCP interceptor — captures MCP tool calls."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Optional

from ahp.core.records import ActionPayload, Authorization
from ahp.core.types import ActionType, AuthorizationType, Protocol, ResultStatus


def _hash16(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()[:16]


def create_action_from_mcp(
    tool_name: str,
    parameters: dict,
    result: Any,
    duration_ms: int,
    success: bool = True,
    target_entity: str = "",
    filter_pipeline: Optional[Any] = None,
) -> ActionPayload:
    """Create an ActionPayload from an MCP tool call."""
    params_bytes = json.dumps(parameters, sort_keys=True).encode("utf-8")
    result_bytes = json.dumps(result, sort_keys=True, default=str).encode("utf-8") if result is not None else b""

    redacted = False
    if filter_pipeline:
        params_hash, _, r1 = filter_pipeline.hash_payload(params_bytes, "parameters")
        result_hash, _, r2 = filter_pipeline.hash_payload(result_bytes, "results")
        redacted = r1 or r2
    else:
        params_hash = _hash16(params_bytes)
        result_hash = _hash16(result_bytes) if result_bytes else b"\x00" * 16

    return ActionPayload(
        tool_name=tool_name,
        parameters_hash=params_hash,
        result_hash=result_hash,
        result_status=ResultStatus.SUCCESS if success else ResultStatus.ERROR,
        response_time_ms=duration_ms,
        protocol=Protocol.MCP,
        action_type=ActionType.TOOL_CALL,
        target_entity=target_entity,
        redacted=redacted,
        authorization=Authorization(type=AuthorizationType.AUTH_NONE),
    )
