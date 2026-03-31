"""Decorator-based instrumentation — @trace_tool, @trace_llm, @trace_agent.

Auto-captures input args, return value, duration, and success/failure
for any Python function. Works with both sync and async functions.

Usage:
    import ahp

    ahp.set_default_recorder(recorder)

    @ahp.trace_tool
    def web_search(query: str) -> dict:
        return results

    @ahp.trace_llm(model_id="gpt-4o", provider="openai")
    def call_llm(prompt: str) -> str:
        return response

    @ahp.trace_agent
    async def delegate(task: str) -> str:
        return await sub_agent.run(task)
"""

from __future__ import annotations

import functools
import inspect
import json
import time
from typing import Any, Callable, Optional

from ahp._globals import get_default_recorder
from ahp.core.types import ActionType, Protocol, ResultStatus

_MAX_PAYLOAD = 65536  # 64KB — matches MAX_STRING_LENGTH in validation.py


def _serialize_args(args: tuple, kwargs: dict) -> bytes:
    """Serialize function arguments to JSON bytes. Falls back to repr()."""
    try:
        data = {"args": list(args), "kwargs": kwargs}
        result = json.dumps(data, default=str, ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError, OverflowError):
        result = repr({"args": args, "kwargs": kwargs}).encode("utf-8")
    if len(result) > _MAX_PAYLOAD:
        result = result[:_MAX_PAYLOAD]
    return result


def _serialize_result(value: Any) -> bytes:
    """Serialize a return value to JSON bytes. Falls back to repr()."""
    try:
        result = json.dumps(value, default=str, ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError, OverflowError):
        result = repr(value).encode("utf-8")
    if len(result) > _MAX_PAYLOAD:
        result = result[:_MAX_PAYLOAD]
    return result


_RECORD_KWARGS_KEYS = (
    "tool_name",
    "parameters",
    "result",
    "action_type",
    "protocol",
    "result_status",
    "response_time_ms",
    "model_id",
    "provider",
)


def _build_record_kwargs(
    tool_name: str,
    params: bytes,
    result_bytes: bytes,
    action_type: ActionType,
    protocol: Protocol,
    result_status: ResultStatus,
    duration_ms: int,
    model_id: str = "",
    provider: str = "",
) -> dict:
    """Build kwargs dict for safe_record."""
    return {
        "tool_name": tool_name,
        "parameters": params,
        "result": result_bytes,
        "action_type": action_type,
        "protocol": protocol,
        "result_status": result_status,
        "response_time_ms": duration_ms,
        "model_id": model_id,
        "provider": provider,
    }


def _record(rec: Any, **kwargs: Any) -> None:
    """Call safe_record on a sync recorder (fail-open)."""
    try:
        rec.safe_record(**kwargs)
    except Exception:
        pass  # Fail-open: never crash the decorated function


async def _async_record(rec: Any, **kwargs: Any) -> None:
    """Call safe_record on any recorder, awaiting if async (fail-open)."""
    try:
        result = rec.safe_record(**kwargs)
        if inspect.isawaitable(result):
            await result
    except Exception:
        pass  # Fail-open: never crash the decorated function


def _make_decorator(
    fn: Optional[Callable],
    *,
    tool_name: str,
    action_type: ActionType,
    protocol: Protocol,
    recorder: Optional[Any],
    model_id: str,
    provider: str,
) -> Any:
    """Shared decorator factory for trace_tool, trace_llm, trace_agent."""

    def decorator(func: Callable) -> Callable:
        name = tool_name or func.__name__

        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                rec = recorder or get_default_recorder()
                params = _serialize_args(args, kwargs)
                start = time.time()
                try:
                    result = await func(*args, **kwargs)
                except Exception as exc:
                    duration_ms = int((time.time() - start) * 1000)
                    if rec:
                        kw = _build_record_kwargs(
                            name,
                            params,
                            _serialize_result(str(exc)),
                            action_type,
                            protocol,
                            ResultStatus.ERROR,
                            duration_ms,
                            model_id=model_id,
                            provider=provider,
                        )
                        await _async_record(rec, **kw)
                    raise
                duration_ms = int((time.time() - start) * 1000)
                if rec:
                    kw = _build_record_kwargs(
                        name,
                        params,
                        _serialize_result(result),
                        action_type,
                        protocol,
                        ResultStatus.SUCCESS,
                        duration_ms,
                        model_id=model_id,
                        provider=provider,
                    )
                    await _async_record(rec, **kw)
                return result

            return async_wrapper

        else:

            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                rec = recorder or get_default_recorder()
                params = _serialize_args(args, kwargs)
                start = time.time()
                try:
                    result = func(*args, **kwargs)
                except Exception as exc:
                    duration_ms = int((time.time() - start) * 1000)
                    if rec:
                        kw = _build_record_kwargs(
                            name,
                            params,
                            _serialize_result(str(exc)),
                            action_type,
                            protocol,
                            ResultStatus.ERROR,
                            duration_ms,
                            model_id=model_id,
                            provider=provider,
                        )
                        _record(rec, **kw)
                    raise
                duration_ms = int((time.time() - start) * 1000)
                if rec:
                    kw = _build_record_kwargs(
                        name,
                        params,
                        _serialize_result(result),
                        action_type,
                        protocol,
                        ResultStatus.SUCCESS,
                        duration_ms,
                        model_id=model_id,
                        provider=provider,
                    )
                    _record(rec, **kw)
                return result

            return sync_wrapper

    if fn is not None:
        # Bare decorator: @trace_tool
        return decorator(fn)
    # Decorator with arguments: @trace_tool(...)
    return decorator


def trace_tool(
    fn: Optional[Callable] = None,
    *,
    tool_name: str = "",
    protocol: Protocol = Protocol.CUSTOM,
    recorder: Optional[Any] = None,
) -> Any:
    """Decorator that records a function call as a TOOL_CALL action.

    Can be used bare or with arguments::

        @trace_tool
        def search(query): ...

        @trace_tool(tool_name="custom_search", protocol=Protocol.MCP)
        def search(query): ...
    """
    return _make_decorator(
        fn,
        tool_name=tool_name,
        action_type=ActionType.TOOL_CALL,
        protocol=protocol,
        recorder=recorder,
        model_id="",
        provider="",
    )


def trace_llm(
    fn: Optional[Callable] = None,
    *,
    tool_name: str = "",
    model_id: str = "",
    provider: str = "",
    protocol: Protocol = Protocol.HTTP,
    recorder: Optional[Any] = None,
) -> Any:
    """Decorator that records a function call as an INFERENCE action.

    Usage::

        @trace_llm(model_id="gpt-4o", provider="openai")
        def call_openai(prompt: str) -> str: ...
    """
    return _make_decorator(
        fn,
        tool_name=tool_name,
        action_type=ActionType.INFERENCE,
        protocol=protocol,
        recorder=recorder,
        model_id=model_id,
        provider=provider,
    )


def trace_agent(
    fn: Optional[Callable] = None,
    *,
    tool_name: str = "",
    protocol: Protocol = Protocol.CUSTOM,
    recorder: Optional[Any] = None,
) -> Any:
    """Decorator that records a function call as a DELEGATION action.

    Usage::

        @trace_agent
        async def delegate_to_researcher(task: str) -> str: ...
    """
    return _make_decorator(
        fn,
        tool_name=tool_name,
        action_type=ActionType.DELEGATION,
        protocol=protocol,
        recorder=recorder,
        model_id="",
        provider="",
    )
