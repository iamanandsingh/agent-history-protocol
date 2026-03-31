"""OpenAI client wrapper — auto-records all LLM calls to AHP.

Usage:
    from ahp.adapters.openai import instrument
    import openai

    client = instrument(openai.OpenAI())
    # All chat.completions.create() calls are now recorded in AHP

    # Or with explicit recorder:
    client = instrument(openai.OpenAI(), recorder=my_recorder)
"""

from __future__ import annotations

import json
import time
from typing import Any, Iterator, Optional

from ahp._globals import get_default_recorder
from ahp.core.pricing import estimate_cost_nano
from ahp.core.types import ActionType, Protocol, ResultStatus


def _safe_int(val: Any) -> int:
    """Convert to int, returning 0 for None/invalid."""
    if val is None:
        return 0
    try:
        return int(val)
    except (ValueError, TypeError):
        return 0


def _extract_usage(response: Any) -> dict:
    """Extract token counts from an OpenAI response object."""
    usage = getattr(response, "usage", None)
    if usage is None:
        return {
            "input_tokens": 0,
            "output_tokens": 0,
            "cache_read": 0,
            "reasoning": 0,
        }

    input_t = _safe_int(getattr(usage, "prompt_tokens", 0) or getattr(usage, "input_tokens", 0))
    output_t = _safe_int(getattr(usage, "completion_tokens", 0) or getattr(usage, "output_tokens", 0))

    # Cached tokens
    cache_read = 0
    for details_attr in ("prompt_tokens_details", "input_tokens_details"):
        details = getattr(usage, details_attr, None)
        if details is not None:
            cache_read = _safe_int(getattr(details, "cached_tokens", 0))
            if cache_read:
                break

    # Reasoning tokens
    reasoning = 0
    for details_attr in ("completion_tokens_details", "output_tokens_details"):
        details = getattr(usage, details_attr, None)
        if details is not None:
            reasoning = _safe_int(getattr(details, "reasoning_tokens", 0))
            if reasoning:
                break

    return {
        "input_tokens": input_t,
        "output_tokens": output_t,
        "cache_read": cache_read,
        "reasoning": reasoning,
    }


def _record_inference(
    rec: Any,
    model_id: str,
    params_bytes: bytes,
    result_bytes: bytes,
    usage: dict,
    duration_ms: int,
    status: ResultStatus,
    cost_nano: Optional[int] = None,
) -> None:
    """Record an inference via the recorder (fail-open)."""
    if cost_nano is None:
        cost_nano = estimate_cost_nano(model_id, usage["input_tokens"], usage["output_tokens"])

    try:
        result = rec.safe_record(
            tool_name="openai.chat.completions",
            parameters=params_bytes,
            result=result_bytes,
            protocol=Protocol.HTTP,
            action_type=ActionType.INFERENCE,
            result_status=status,
            response_time_ms=duration_ms,
            model_id=model_id,
            input_token_count=usage["input_tokens"],
            output_token_count=usage["output_tokens"],
            cache_read_tokens=usage["cache_read"],
            reasoning_tokens=usage["reasoning"],
            cost_nano_usd=cost_nano,
            provider="openai",
            target_entity="api.openai.com",
        )
        # Handle async recorders
        import inspect

        if inspect.isawaitable(result):
            # Can't await in sync context — the coroutine will be GC'd.
            # This is acceptable: sync instrument() is designed for sync OpenAI client.
            pass
    except Exception:
        pass  # Fail-open


class _InstrumentedCompletions:
    """Wraps chat.completions to intercept create() calls."""

    def __init__(self, original: Any, recorder: Optional[Any]) -> None:
        self._original = original
        self._recorder = recorder

    def create(self, **kwargs: Any) -> Any:
        rec = self._recorder or get_default_recorder()
        stream = kwargs.get("stream", False)
        model = kwargs.get("model", "")

        # Serialize params (strip messages content to avoid huge payloads)
        try:
            params_summary = {k: v for k, v in kwargs.items() if k != "messages"}
            params_summary["message_count"] = len(kwargs.get("messages", []))
            params_bytes = json.dumps(params_summary, default=str).encode("utf-8")[:65536]
        except Exception:
            params_bytes = b"{}"

        start = time.time()

        if stream:
            # Inject stream_options to get usage in final chunk
            if "stream_options" not in kwargs:
                kwargs["stream_options"] = {"include_usage": True}
            elif isinstance(kwargs["stream_options"], dict):
                kwargs["stream_options"].setdefault("include_usage", True)

            try:
                stream_response = self._original.create(**kwargs)
                return _StreamWrapper(stream_response, rec, model, params_bytes, start)
            except Exception as exc:
                duration_ms = int((time.time() - start) * 1000)
                if rec:
                    _record_inference(
                        rec,
                        model,
                        params_bytes,
                        str(exc).encode("utf-8")[:65536],
                        {"input_tokens": 0, "output_tokens": 0, "cache_read": 0, "reasoning": 0},
                        duration_ms,
                        ResultStatus.ERROR,
                    )
                raise

        # Non-streaming
        try:
            response = self._original.create(**kwargs)
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            if rec:
                _record_inference(
                    rec,
                    model,
                    params_bytes,
                    str(exc).encode("utf-8")[:65536],
                    {"input_tokens": 0, "output_tokens": 0, "cache_read": 0, "reasoning": 0},
                    duration_ms,
                    ResultStatus.ERROR,
                )
            raise

        duration_ms = int((time.time() - start) * 1000)

        if rec:
            usage = _extract_usage(response)
            response_model = getattr(response, "model", model) or model

            try:
                result_bytes = response.model_dump_json().encode("utf-8")[:65536]
            except Exception:
                result_bytes = b"{}"

            _record_inference(rec, response_model, params_bytes, result_bytes, usage, duration_ms, ResultStatus.SUCCESS)

        return response

    def __getattr__(self, name: str) -> Any:
        return getattr(self._original, name)


class _StreamWrapper:
    """Wraps an OpenAI streaming response to record after stream completes."""

    def __init__(
        self,
        stream: Any,
        recorder: Optional[Any],
        model: str,
        params_bytes: bytes,
        start_time: float,
    ) -> None:
        self._stream = stream
        self._recorder = recorder
        self._model = model
        self._params_bytes = params_bytes
        self._start_time = start_time
        self._usage: Optional[dict] = None
        self._response_model: Optional[str] = None

    def __iter__(self) -> Iterator:
        try:
            for chunk in self._stream:
                # Extract usage from the final chunk (when stream_options.include_usage=True)
                chunk_usage = getattr(chunk, "usage", None)
                if chunk_usage is not None:
                    self._usage = _extract_usage(chunk)
                chunk_model = getattr(chunk, "model", None)
                if chunk_model:
                    self._response_model = chunk_model
                yield chunk
        finally:
            self._record()

    def __enter__(self) -> "_StreamWrapper":
        return self

    def __exit__(self, *args: Any) -> None:
        # Ensure stream is consumed and recorded if used with `with`
        try:
            self._stream.close()
        except Exception:
            pass

    def _record(self) -> None:
        rec = self._recorder
        if rec is None:
            return

        duration_ms = int((time.time() - self._start_time) * 1000)
        model = self._response_model or self._model
        usage = self._usage or {"input_tokens": 0, "output_tokens": 0, "cache_read": 0, "reasoning": 0}

        _record_inference(
            rec,
            model,
            self._params_bytes,
            b'{"stream": true}',
            usage,
            duration_ms,
            ResultStatus.SUCCESS,
        )


class _InstrumentedChat:
    """Wraps client.chat to intercept chat.completions."""

    def __init__(self, original_chat: Any, recorder: Optional[Any]) -> None:
        self._original = original_chat
        self.completions = _InstrumentedCompletions(original_chat.completions, recorder)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._original, name)


def instrument(client: Any, recorder: Optional[Any] = None) -> Any:
    """Instrument an OpenAI client to auto-record all LLM calls.

    Args:
        client: An ``openai.OpenAI()`` instance.
        recorder: Optional AHPRecorder. Falls back to ``get_default_recorder()``.

    Returns:
        The same client with ``chat.completions.create()`` instrumented.

    Example::

        from ahp.adapters.openai import instrument
        import openai

        client = instrument(openai.OpenAI())
        response = client.chat.completions.create(
            model="gpt-4o", messages=[{"role": "user", "content": "Hello"}]
        )
        # Automatically recorded in AHP with model, tokens, cost, provider
    """
    client.chat = _InstrumentedChat(client.chat, recorder)
    return client
