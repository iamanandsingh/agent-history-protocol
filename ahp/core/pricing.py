"""Model pricing — configurable cost estimation for LLM calls.

Pricing is expressed as nano USD per token (1 USD = 1,000,000,000 nano USD).
Users can override via ahp.yaml pricing section or by calling set_pricing().

Built-in defaults are best-effort snapshots and WILL go stale.
Always configure your own rates for accurate cost tracking.
"""

from __future__ import annotations

import threading
from typing import Dict, Optional, Tuple

# Max value for uint64 serialization
_MAX_UINT64 = (2**64) - 1

# Format: "model_prefix": (input_nano_per_token, output_nano_per_token)
# These are fallback defaults. Users should configure their own via ahp.yaml.
# Longer prefixes take priority (e.g. "gpt-4o" wins over "gpt-4").
# Last verified: 2026-03-31. Prices change — always configure your own.
_BUILTIN_PRICING: Dict[str, Tuple[int, int]] = {
    # OpenAI — current models
    "gpt-4o": (2_500, 10_000),  # $2.50 / $10 per 1M
    "gpt-4o-mini": (150, 600),  # $0.15 / $0.60 per 1M
    "gpt-4.1": (2_000, 8_000),  # $2 / $8 per 1M
    "gpt-4.1-mini": (400, 1_600),  # $0.40 / $1.60 per 1M
    "gpt-4.1-nano": (100, 400),  # $0.10 / $0.40 per 1M
    "o3": (2_000, 8_000),  # $2 / $8 per 1M
    "o3-mini": (1_100, 4_400),  # $1.10 / $4.40 per 1M
    "o4-mini": (1_100, 4_400),  # $1.10 / $4.40 per 1M
    # OpenAI — deprecated (kept for historical chain analysis)
    "gpt-4-turbo": (10_000, 30_000),  # $10 / $30 per 1M (deprecated)
    "gpt-4": (30_000, 60_000),  # $30 / $60 per 1M (deprecated)
    "gpt-3.5-turbo": (500, 1_500),  # $0.50 / $1.50 per 1M (deprecated)
    "o1-mini": (550, 2_200),  # $0.55 / $2.20 per 1M (deprecated Oct 2025)
    "o1": (15_000, 60_000),  # $15 / $60 per 1M (deprecated Oct 2025)
    # Anthropic — specific versions first (longer prefix wins)
    "claude-opus-4-6": (5_000, 25_000),  # $5 / $25 per 1M (Opus 4.6)
    "claude-opus-4-5": (5_000, 25_000),  # $5 / $25 per 1M (Opus 4.5)
    "claude-opus-4-1": (15_000, 75_000),  # $15 / $75 per 1M (Opus 4.1)
    "claude-opus-4-0": (15_000, 75_000),  # $15 / $75 per 1M (Opus 4.0)
    "claude-opus-4": (15_000, 75_000),  # $15 / $75 per 1M (fallback for Opus 4.x)
    "claude-sonnet-4": (3_000, 15_000),  # $3 / $15 per 1M (Sonnet 4/4.5/4.6)
    "claude-haiku-4": (1_000, 5_000),  # $1 / $5 per 1M (Haiku 4.5)
    # Google Gemini — current models
    "gemini-3-flash": (500, 3_000),  # $0.50 / $3 per 1M
    "gemini-3.1": (2_000, 12_000),  # $2 / $12 per 1M (3.1 Pro preview)
    "gemini-2.5-pro": (1_250, 10_000),  # $1.25 / $10 per 1M
    "gemini-2.5-flash-lite": (100, 400),  # $0.10 / $0.40 per 1M
    "gemini-2.5-flash": (300, 2_500),  # $0.30 / $2.50 per 1M
    "gemini-2.0-flash": (100, 400),  # $0.10 / $0.40 per 1M
    # Mistral — current models
    "mistral-large": (500, 1_500),  # $0.50 / $1.50 per 1M (Large 3)
    "mistral-small": (100, 300),  # $0.10 / $0.30 per 1M (Small 3.1)
    # DeepSeek
    "deepseek-r1": (550, 2_190),  # $0.55 / $2.19 per 1M
    "deepseek-v3": (270, 1_100),  # $0.27 / $1.10 per 1M
    "deepseek-chat": (270, 1_100),  # $0.27 / $1.10 per 1M (alias for v3)
}

_lock = threading.Lock()
_active_pricing: Dict[str, Tuple[int, int]] = dict(_BUILTIN_PRICING)


def set_pricing(pricing: Dict[str, Tuple[int, int]], merge: bool = True) -> None:
    """Set the active pricing table.

    Args:
        pricing: Map of model prefix → (input_nano_per_token, output_nano_per_token).
        merge: If True, user entries are merged on top of builtins.
               If False, user entries completely replace builtins.
    """
    global _active_pricing
    with _lock:
        if merge:
            new = dict(_BUILTIN_PRICING)
            new.update(pricing)
            _active_pricing = new
        else:
            _active_pricing = dict(pricing)


def get_pricing() -> Dict[str, Tuple[int, int]]:
    """Return the current active pricing table."""
    with _lock:
        return dict(_active_pricing)


def estimate_cost_nano(model_id: str, input_tokens: int, output_tokens: int) -> int:
    """Estimate cost in nano USD from model + token counts.

    Matches model_id against pricing table prefixes (longest prefix wins).
    Returns 0 for unknown models. Caps at uint64 max to prevent overflow.
    """
    if not model_id or (input_tokens <= 0 and output_tokens <= 0):
        return 0

    model_lower = model_id.lower()

    # Snapshot the dict ref under lock — iteration is safe on the snapshot
    with _lock:
        pricing = _active_pricing

    best_match = ""
    best_rates: Optional[Tuple[int, int]] = None
    for prefix, rates in pricing.items():
        if model_lower.startswith(prefix) and len(prefix) > len(best_match):
            best_match = prefix
            best_rates = rates

    if best_rates is None:
        return 0

    inp_rate, out_rate = best_rates
    result = max(0, input_tokens) * inp_rate + max(0, output_tokens) * out_rate

    if result > _MAX_UINT64:
        return _MAX_UINT64
    return result
