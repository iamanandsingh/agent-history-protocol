"""PII filter pipeline — Section 10.2 of the AHP specification."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, List, Optional, Tuple

# Use PCRE2-compatible regex if available, fall back to stdlib re
try:
    import regex as re_engine

    PCRE2 = True
except ImportError:
    import re as re_engine  # type: ignore

    PCRE2 = False


@dataclass
class Filter:
    name: str
    pattern: str
    replacement: str
    scope: List[str] = field(default_factory=lambda: ["parameters", "results"])
    _compiled: Optional[Any] = field(default=None, repr=False)

    def compile(self) -> None:
        self._compiled = re_engine.compile(self.pattern)

    def apply(self, text: str) -> Tuple[str, bool]:
        """Apply filter. Returns (filtered_text, did_match)."""
        if self._compiled is None:
            self.compile()
        if self._compiled is None:
            raise RuntimeError(f"Filter '{self.name}': compile() failed to set _compiled")
        result, count = self._compiled.subn(self.replacement, text)
        return result, count > 0


# Built-in presets (Section 10.3)
PRESETS = {
    "pci": [
        Filter(name="credit_card", pattern=r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b", replacement="[REDACTED:CC]"),
        Filter(name="cvv", pattern=r"\b\d{3,4}\b(?=.{0,40}(?:cvv|cvc|security))", replacement="[REDACTED:CVV]"),
    ],
    "pii-us": [
        Filter(name="ssn", pattern=r"\b\d{3}-\d{2}-\d{4}\b", replacement="[REDACTED:SSN]"),
    ],
    "credentials": [
        Filter(name="bearer_token", pattern=r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", replacement="Bearer [REDACTED:TOKEN]"),
        Filter(
            name="api_key",
            pattern=r'(?:api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*["\']?[A-Za-z0-9\-._~+/]{16,}["\']?',
            replacement="[REDACTED:API_KEY]",
            scope=["all"],
        ),
        Filter(
            name="password",
            pattern=r'(?:password|passwd|pwd)\s*[:=]\s*["\']?[^\s"\']{4,}["\']?',
            replacement="[REDACTED:PASSWORD]",
            scope=["all"],
        ),
    ],
    "pii-eu": [
        Filter(name="iban", pattern=r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}[A-Z0-9]{0,16}\b", replacement="[REDACTED:IBAN]"),
        Filter(name="eu_national_id", pattern=r"\b[A-Z]{1,2}\d{6,9}[A-Z]?\b", replacement="[REDACTED:EU_ID]"),
        Filter(name="eu_passport", pattern=r"\b[A-Z]{1,2}\d{7,8}\b", replacement="[REDACTED:PASSPORT]"),
    ],
    "hipaa": [
        Filter(name="mrn", pattern=r"\bMRN[-:\s]*\d{6,10}\b", replacement="[REDACTED:MRN]"),
        Filter(
            name="dob",
            pattern=r"\b(?:DOB|Date of Birth)[-:\s]*\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}\b",
            replacement="[REDACTED:DOB]",
            scope=["all"],
        ),
        Filter(
            name="phone_us",
            pattern=r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
            replacement="[REDACTED:PHONE]",
        ),
        Filter(
            name="email", pattern=r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", replacement="[REDACTED:EMAIL]"
        ),
    ],
}


class FilterPipeline:
    """Applies PII filters in order, computes hashes."""

    def __init__(self, filters: Optional[List[Filter]] = None, presets: Optional[List[str]] = None):
        self.filters: List[Filter] = []
        if presets:
            for preset_name in presets:
                if preset_name in PRESETS:
                    self.filters.extend(PRESETS[preset_name])
        if filters:
            self.filters.extend(filters)
        for f in self.filters:
            f.compile()
        # Pre-partition by scope to avoid per-payload membership checks
        self._param_filters = [f for f in self.filters if "parameters" in f.scope or "all" in f.scope]
        self._result_filters = [f for f in self.filters if "results" in f.scope or "all" in f.scope]

    def apply(self, payload: bytes, scope: str = "parameters") -> Tuple[bytes, bool]:
        """Apply all matching filters. Returns (filtered_bytes, was_redacted)."""
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError:
            return payload, False  # Binary payload — filters don't apply

        active = self._param_filters if scope == "parameters" else self._result_filters
        redacted = False
        for f in active:
            text, matched = f.apply(text)
            if matched:
                redacted = True

        return text.encode("utf-8"), redacted

    def hash_payload(self, payload: bytes, scope: str = "parameters") -> Tuple[bytes, bytes, bool]:
        """Filter then hash. Returns (hash_16, filtered_bytes, was_redacted)."""
        filtered, redacted = self.apply(payload, scope)
        hash_16 = hashlib.sha256(filtered).digest()[:16]
        return hash_16, filtered, redacted

    def config_hash(self) -> bytes:
        """SHA-256 of canonical filter config for BootRecord."""
        if not self.filters:
            return b"\x00" * 32
        config = json.dumps(
            [
                {"name": f.name, "pattern": f.pattern, "replacement": f.replacement, "scope": sorted(f.scope)}
                for f in self.filters
            ],
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(config).digest()
