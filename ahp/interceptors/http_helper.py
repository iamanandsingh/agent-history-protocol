"""HTTP interceptor — auto-captures HTTP calls and LLM API requests."""

from __future__ import annotations

import hashlib
import re
from typing import Any, Optional, Tuple

from ahp.core.records import ActionPayload, Authorization
from ahp.core.types import ActionType, AuthorizationType, Protocol, ResultStatus

# Built-in LLM API endpoint patterns — auto-detect INFERENCE.
# Users can add custom patterns via ahp.yaml `providers` section.
_BUILTIN_PATTERNS = [
    (re.compile(r"api\.openai\.com/v\d+/chat/completions"), "openai.chat.completions", "openai"),
    (re.compile(r"[\w-]+\.openai\.azure\.com"), "azure.openai.chat", "azure-openai"),
    (re.compile(r"api\.anthropic\.com/v\d+/messages"), "anthropic.messages", "anthropic"),
    (re.compile(r"generativelanguage\.googleapis\.com"), "google.generateContent", "google"),
    (re.compile(r"aiplatform\.googleapis\.com"), "google.vertex.predict", "google-vertex"),
    (re.compile(r"api\.cohere\.ai/v\d+/chat"), "cohere.chat", "cohere"),
    (re.compile(r"api\.mistral\.ai"), "mistral.chat", "mistral"),
    (re.compile(r"bedrock-runtime\..+\.amazonaws\.com"), "aws.bedrock.invoke", "aws-bedrock"),
    (re.compile(r"api\.groq\.com"), "groq.chat.completions", "groq"),
    (re.compile(r"api\.together\.xyz"), "together.chat.completions", "together"),
    (re.compile(r"api\.fireworks\.ai"), "fireworks.chat.completions", "fireworks"),
    (re.compile(r"api\.deepseek\.com"), "deepseek.chat.completions", "deepseek"),
    (re.compile(r"api\.perplexity\.ai"), "perplexity.chat.completions", "perplexity"),
]

# Active patterns — builtins + user-configured. User patterns checked first.
_custom_patterns: list = []


def add_provider_patterns(patterns: list) -> None:
    """Add custom provider URL patterns (checked before builtins).

    Args:
        patterns: List of (regex_string, tool_name, provider) tuples.
    """
    for pat_str, name, provider in patterns:
        try:
            _custom_patterns.append((re.compile(pat_str), name, provider))
        except re.error:
            pass  # Skip invalid regex silently


def _hash16(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()[:16]


def _detect_llm(url: str) -> Tuple[Optional[str], str]:
    """Check if URL matches known LLM API endpoints. Returns (tool_name, provider) or (None, "").

    User-configured patterns are checked first, then builtins.
    """
    for pattern, name, provider in _custom_patterns:
        if pattern.search(url):
            return name, provider
    for pattern, name, provider in _BUILTIN_PATTERNS:
        if pattern.search(url):
            return name, provider
    return None, ""


def _extract_model_id(body: bytes, url: str = "") -> str:
    """Try to extract model ID from request body or URL."""
    # Try request body first (OpenAI, Anthropic, Mistral)
    try:
        import json

        data = json.loads(body)
        model = data.get("model", "")
        if model:
            return model
    except Exception:
        pass

    # Try URL (Gemini: /models/{model_id}:generateContent)
    if url:
        match = re.search(r"/models/([^/:]+)", url)
        if match:
            return match.group(1)

    return ""


def _safe_int(val: Any) -> int:
    """Convert a value to int, returning 0 for None/invalid."""
    if val is None:
        return 0
    try:
        return int(val)
    except (ValueError, TypeError):
        return 0


def _extract_tokens(body: bytes) -> Tuple[int, int, int, int, int]:
    """Try to extract token counts from LLM response (OpenAI, Anthropic, Gemini).

    Returns (input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens, reasoning_tokens).
    """
    try:
        import json

        data = json.loads(body)
        # OpenAI / Anthropic / DeepSeek format
        usage = data.get("usage")
        if isinstance(usage, dict):
            input_t = _safe_int(usage.get("input_tokens") or usage.get("prompt_tokens"))
            output_t = _safe_int(usage.get("output_tokens") or usage.get("completion_tokens"))

            # Cached tokens — check both Chat Completions and Responses API field names
            cache_read = 0
            for details_key in ("prompt_tokens_details", "input_tokens_details"):
                details = usage.get(details_key)
                if isinstance(details, dict):
                    cache_read = _safe_int(details.get("cached_tokens"))
                    if cache_read:
                        break

            # Anthropic cached tokens
            cache_creation = _safe_int(usage.get("cache_creation_input_tokens"))
            cache_read = cache_read or _safe_int(usage.get("cache_read_input_tokens"))

            # Reasoning tokens (o3, o4-mini, DeepSeek-R1) — check both API styles
            reasoning = 0
            for details_key in ("completion_tokens_details", "output_tokens_details"):
                details = usage.get(details_key)
                if isinstance(details, dict):
                    reasoning = _safe_int(details.get("reasoning_tokens"))
                    if reasoning:
                        break

            return input_t, output_t, cache_read, cache_creation, reasoning
        # Gemini format
        usage_meta = data.get("usageMetadata")
        if isinstance(usage_meta, dict):
            return (
                _safe_int(usage_meta.get("promptTokenCount")),
                _safe_int(usage_meta.get("candidatesTokenCount")),
                _safe_int(usage_meta.get("cachedContentTokenCount")),
                0,
                _safe_int(usage_meta.get("thoughtsTokenCount")),
            )
        return 0, 0, 0, 0, 0
    except (json.JSONDecodeError, ValueError, TypeError):
        return 0, 0, 0, 0, 0


def create_action_from_http(
    method: str,
    url: str,
    request_body: bytes,
    response_body: bytes,
    status_code: int,
    duration_ms: int,
    filter_pipeline: Optional[Any] = None,
) -> ActionPayload:
    """Create an ActionPayload from an HTTP request/response pair."""
    llm_name, provider = _detect_llm(url)
    is_inference = llm_name is not None

    # Apply PII filters if configured
    redacted = False
    if filter_pipeline:
        params_hash, filtered_params, r1 = filter_pipeline.hash_payload(request_body, "parameters")
        result_hash, filtered_result, r2 = filter_pipeline.hash_payload(response_body, "results")
        redacted = r1 or r2
    else:
        params_hash = _hash16(request_body) if request_body else b"\x00" * 16
        result_hash = _hash16(response_body) if response_body else b"\x00" * 16

    # Determine result status
    if status_code >= 200 and status_code < 300:
        result_status = ResultStatus.SUCCESS
    elif status_code == 408 or status_code == 504:
        result_status = ResultStatus.TIMEOUT
    elif status_code >= 400:
        result_status = ResultStatus.ERROR
    else:
        result_status = ResultStatus.FAILURE

    model_id = ""
    input_tokens = 0
    output_tokens = 0
    cache_read = 0
    cache_creation = 0
    reasoning = 0
    if is_inference:
        model_id = _extract_model_id(request_body, url)
        input_tokens, output_tokens, cache_read, cache_creation, reasoning = _extract_tokens(response_body)

    cost_nano = 0
    if is_inference:
        from ahp.core.pricing import estimate_cost_nano

        cost_nano = estimate_cost_nano(model_id, input_tokens, output_tokens)

    return ActionPayload(
        tool_name=llm_name or f"{method} {url}",
        parameters_hash=params_hash,
        result_hash=result_hash,
        result_status=result_status,
        response_time_ms=duration_ms,
        protocol=Protocol.HTTP,
        action_type=ActionType.INFERENCE if is_inference else ActionType.TOOL_CALL,
        target_entity=url,
        redacted=redacted,
        model_id=model_id,
        input_token_count=input_tokens,
        output_token_count=output_tokens,
        cache_read_tokens=cache_read,
        cache_creation_tokens=cache_creation,
        reasoning_tokens=reasoning,
        cost_nano_usd=cost_nano,
        provider=provider,
        authorization=Authorization(type=AuthorizationType.AUTH_NONE),
    )
