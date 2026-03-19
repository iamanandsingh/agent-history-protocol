"""HTTP interceptor — auto-captures HTTP calls and LLM API requests."""
from __future__ import annotations

import hashlib
import re
from typing import Optional, Callable, Any, Dict, List, Tuple
from ahp.core.types import ResultStatus, Protocol, ActionType, AuthorizationType
from ahp.core.records import ActionPayload, Authorization

# LLM API endpoint patterns — auto-detect INFERENCE
LLM_PATTERNS = [
    (re.compile(r'api\.openai\.com/v\d+/chat/completions'), 'openai.chat.completions'),
    (re.compile(r'api\.anthropic\.com/v\d+/messages'), 'anthropic.messages'),
    (re.compile(r'generativelanguage\.googleapis\.com'), 'google.generateContent'),
    (re.compile(r'api\.cohere\.ai/v\d+/chat'), 'cohere.chat'),
    (re.compile(r'api\.mistral\.ai'), 'mistral.chat'),
]

def _hash16(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()[:16]

def _detect_llm(url: str) -> Optional[str]:
    """Check if URL matches known LLM API endpoints. Returns tool_name or None."""
    for pattern, name in LLM_PATTERNS:
        if pattern.search(url):
            return name
    return None

def _extract_model_id(body: bytes) -> str:
    """Try to extract model ID from request body."""
    try:
        import json
        data = json.loads(body)
        return data.get('model', '')
    except Exception:
        return ''

def _extract_tokens(body: bytes) -> Tuple[int, int]:
    """Try to extract token counts from LLM response (OpenAI, Anthropic, Gemini)."""
    try:
        import json
        data = json.loads(body)
        # OpenAI/Anthropic format
        usage = data.get('usage', {})
        if usage:
            return (
                usage.get('input_tokens', usage.get('prompt_tokens', 0)),
                usage.get('output_tokens', usage.get('completion_tokens', 0)),
            )
        # Gemini format
        usage_meta = data.get('usageMetadata', {})
        if usage_meta:
            return (
                usage_meta.get('promptTokenCount', 0),
                usage_meta.get('candidatesTokenCount', 0),
            )
        return 0, 0
    except Exception:
        return 0, 0

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
    llm_name = _detect_llm(url)
    is_inference = llm_name is not None

    # Apply PII filters if configured
    redacted = False
    if filter_pipeline:
        params_hash, filtered_params, r1 = filter_pipeline.hash_payload(request_body, 'parameters')
        result_hash, filtered_result, r2 = filter_pipeline.hash_payload(response_body, 'results')
        redacted = r1 or r2
    else:
        params_hash = _hash16(request_body) if request_body else b'\x00' * 16
        result_hash = _hash16(response_body) if response_body else b'\x00' * 16

    # Determine result status
    if status_code >= 200 and status_code < 300:
        result_status = ResultStatus.SUCCESS
    elif status_code == 408 or status_code == 504:
        result_status = ResultStatus.TIMEOUT
    elif status_code >= 400:
        result_status = ResultStatus.ERROR
    else:
        result_status = ResultStatus.FAILURE

    model_id = ''
    input_tokens = 0
    output_tokens = 0
    if is_inference:
        model_id = _extract_model_id(request_body)
        input_tokens, output_tokens = _extract_tokens(response_body)

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
        authorization=Authorization(type=AuthorizationType.AUTH_NONE),
    )
