"""Gemini LLM client with transparent AHP interception.

Makes REAL HTTP calls to Google's Gemini API.
AHP records every call automatically.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from ahp.core.chain import ChainWriter
from ahp.core.uuid7 import uuid7
from ahp.interceptors.http_helper import create_action_from_http


class GeminiClient:
    """Calls Gemini API and records every call in AHP chain."""

    def __init__(
        self, api_key: str, model: str, endpoint: str, writer: ChainWriter, session_id: Optional[bytes] = None
    ):
        self.api_key = api_key
        self.model = model
        self.endpoint = endpoint
        self.writer = writer
        self.session_id = session_id or uuid7()
        self.last_record_id: Optional[bytes] = None

    def chat(self, messages: List[Dict[str, str]], system_prompt: str = "") -> Dict[str, Any]:
        """Send messages to Gemini and return the response.

        Messages format: [{"role": "user", "content": "..."}, ...]
        Returns: {"text": "...", "input_tokens": N, "output_tokens": N, "raw": {...}}
        """
        # Build Gemini request
        contents = []
        for msg in messages:
            role = "user" if msg["role"] == "user" else "model"
            contents.append(
                {
                    "role": role,
                    "parts": [{"text": msg["content"]}],
                }
            )

        body = {"contents": contents}
        if system_prompt:
            body["systemInstruction"] = {"parts": [{"text": system_prompt}]}
        body["generationConfig"] = {
            "temperature": 0.7,
            "maxOutputTokens": 1024,
        }

        url = f"{self.endpoint}?key={self.api_key}"
        request_bytes = json.dumps(body).encode()

        # Make REAL HTTP call
        start = time.time()
        status_code = 200
        response_bytes = b""

        try:
            req = Request(url, data=request_bytes, headers={"Content-Type": "application/json"})
            with urlopen(req, timeout=30) as resp:
                response_bytes = resp.read()
                status_code = resp.status
        except HTTPError as e:
            response_bytes = e.read() if hasattr(e, "read") else str(e).encode()
            status_code = e.code
        except URLError as e:
            response_bytes = str(e).encode()
            status_code = 500
        except Exception as e:
            response_bytes = str(e).encode()
            status_code = 500

        duration_ms = int((time.time() - start) * 1000)

        # Record in AHP — the interceptor auto-detects Gemini as INFERENCE
        # Strip the API key from the URL for recording (security)
        safe_url = self.endpoint  # without ?key=...
        action = create_action_from_http(
            method="POST",
            url=safe_url,
            request_body=request_bytes,
            response_body=response_bytes,
            status_code=status_code,
            duration_ms=duration_ms,
        )
        # Override model_id since Gemini puts it in the URL, not the request body
        action.model_id = self.model

        # Link to previous inference (conversational continuity)
        if self.last_record_id:
            action.parent_action_id = self.last_record_id

        record = self.writer.write_record(action, session_id=self.session_id)
        self.last_record_id = record.record_id

        # Parse Gemini response
        result = self._parse_response(response_bytes, status_code, duration_ms)
        return result

    def _parse_response(self, response_bytes: bytes, status_code: int, duration_ms: int) -> Dict[str, Any]:
        """Parse Gemini API response."""
        if status_code != 200:
            error_text = response_bytes.decode("utf-8", errors="replace")
            return {
                "text": f"[ERROR {status_code}]: {error_text[:200]}",
                "input_tokens": 0,
                "output_tokens": 0,
                "error": True,
                "status_code": status_code,
                "duration_ms": duration_ms,
            }

        try:
            data = json.loads(response_bytes)
            candidates = data.get("candidates", [])
            text = ""
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                text = "".join(p.get("text", "") for p in parts)

            usage = data.get("usageMetadata", {})
            return {
                "text": text,
                "input_tokens": usage.get("promptTokenCount", 0),
                "output_tokens": usage.get("candidatesTokenCount", 0),
                "error": False,
                "duration_ms": duration_ms,
                "raw": data,
            }
        except Exception as e:
            return {
                "text": f"[PARSE ERROR]: {e}",
                "input_tokens": 0,
                "output_tokens": 0,
                "error": True,
                "duration_ms": duration_ms,
            }
