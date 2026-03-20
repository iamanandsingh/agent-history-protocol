"""Transparent HTTP interceptor -- monkey-patches urllib.request.urlopen.

When activated, ALL HTTP calls made via urllib.request are automatically
captured and recorded in AHP. No code changes needed in the agent.

Usage:
    from ahp.interceptors.http_auto import install_http_interceptor

    recorder = AHPRecorder(agent_name="my-agent")
    install_http_interceptor(recorder)

    # Now ANY urllib call is recorded:
    urlopen("https://api.example.com/data")  # <- AHP records this automatically
"""

from __future__ import annotations

import io
import logging
import socket
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Optional

from ahp.interceptors.http_helper import create_action_from_http

logger = logging.getLogger("ahp.interceptors.http_auto")

# Module-level state for the monkey-patch (guarded by _install_lock).
_original_urlopen = None  # type: Optional[Any]
_recorder = None  # type: Optional[Any]
_install_lock = threading.Lock()

# Per-thread reentrancy guard: prevents the witness client's own urllib calls
# (made during AHP recording) from being intercepted and recorded again.
_local = threading.local()

# The sentinel that urllib.request.urlopen uses for the default timeout.
_GLOBAL_DEFAULT_TIMEOUT = socket._GLOBAL_DEFAULT_TIMEOUT  # type: ignore[attr-defined]


class _ReadableResponse:
    """Wraps an already-read http.client.HTTPResponse so callers can still
    call read(), readline(), use it as a context manager, etc.

    The real response body has already been consumed for AHP hashing;
    this wrapper replays it from an in-memory buffer.
    """

    def __init__(self, original: Any, body: bytes) -> None:
        self._original = original
        self._body = body
        self._stream = io.BytesIO(body)
        # Forward the public attributes that callers expect.
        self.status = original.status
        self.headers = original.headers
        self.url = original.url
        self.code = original.code
        self.reason = getattr(original, "reason", "")
        self.msg = getattr(original, "msg", "")
        self.length = len(body)

    # --- reading ---------------------------------------------------------

    def read(self, amt: Optional[int] = None) -> bytes:
        if amt is None:
            return self._stream.read()
        return self._stream.read(amt)

    def readline(self, limit: int = -1) -> bytes:
        return self._stream.readline(limit)

    def readlines(self, hint: int = -1) -> list:
        return self._stream.readlines(hint)

    def readable(self) -> bool:
        return True

    # --- context-manager -------------------------------------------------

    def __enter__(self) -> "_ReadableResponse":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    # --- pass-through helpers -------------------------------------------

    def close(self) -> None:
        self._original.close()

    def getheader(self, name: str, default: Optional[str] = None) -> Optional[str]:
        return self.headers.get(name, default)

    def getheaders(self) -> list:
        return list(self.headers.items())

    def info(self) -> Any:
        return self.headers

    def geturl(self) -> str:
        return self.url

    def getcode(self) -> int:
        return self.code

    # --- iteration (some callers iterate) --------------------------------

    def __iter__(self):  # type: ignore[override]
        return iter(self._stream)


def install_http_interceptor(recorder: Any) -> None:
    """Install the transparent HTTP interceptor.

    Monkey-patches ``urllib.request.urlopen`` to record all HTTP calls.
    Calling this more than once (without uninstalling first) is a no-op.
    """
    global _original_urlopen, _recorder

    with _install_lock:
        if _original_urlopen is not None:
            return  # Already installed

        _original_urlopen = urllib.request.urlopen
        _recorder = recorder

    def _intercepted_urlopen(
        url: Any,
        data: Any = None,
        timeout: Any = _GLOBAL_DEFAULT_TIMEOUT,
        *,
        cafile: Optional[str] = None,
        capath: Optional[str] = None,
        cadefault: bool = False,
        context: Any = None,
    ) -> Any:
        """Drop-in replacement for urllib.request.urlopen that records calls."""
        # ---- reentrancy guard -------------------------------------------
        # If we're already inside the interceptor (e.g. the witness client
        # making its own HTTP call during AHP recording), pass through
        # directly to avoid infinite recursion and double-recording.
        if getattr(_local, "in_interceptor", False):
            if _original_urlopen is None:
                raise RuntimeError("HTTP interceptor not installed")
            kw: dict[str, Any] = {}
            if timeout is not _GLOBAL_DEFAULT_TIMEOUT:
                kw["timeout"] = timeout
            if cafile is not None:
                kw["cafile"] = cafile
            if capath is not None:
                kw["capath"] = capath
            if context is not None:
                kw["context"] = context
            return _original_urlopen(url, data=data, **kw)

        # ---- extract request metadata -----------------------------------
        if isinstance(url, urllib.request.Request):
            url_str = url.full_url
            method = url.get_method()
            request_body = url.data or b""
        else:
            url_str = str(url)
            method = "POST" if data else "GET"
            request_body = data or b""

        if isinstance(request_body, str):
            request_body = request_body.encode("utf-8")

        # ---- build kwargs for the real urlopen --------------------------
        kwargs = {}  # type: dict[str, Any]
        if timeout is not _GLOBAL_DEFAULT_TIMEOUT:
            kwargs["timeout"] = timeout
        if cafile is not None:
            kwargs["cafile"] = cafile
        if capath is not None:
            kwargs["capath"] = capath
        if context is not None:
            kwargs["context"] = context

        # ---- execute the real HTTP call ---------------------------------
        start = time.time()
        response_body = b""
        status_code = 0
        error = None  # type: Optional[Exception]
        wrapped = None  # type: Optional[_ReadableResponse]

        try:
            if _original_urlopen is None:
                raise RuntimeError("HTTP interceptor is not installed; call install_http_interceptor() first")
            response = _original_urlopen(url, data=data, **kwargs)

            # Read the full body so we can hash it for AHP, then wrap the
            # response so the caller can still read() it.
            response_body = response.read()
            status_code = response.status
            wrapped = _ReadableResponse(response, response_body)

        except urllib.error.HTTPError as exc:
            status_code = exc.code
            try:
                response_body = exc.read()
            except Exception:
                response_body = str(exc).encode("utf-8")
            error = exc

        except urllib.error.URLError as exc:
            status_code = 0
            response_body = str(exc).encode("utf-8")
            error = exc

        except Exception as exc:
            status_code = 0
            response_body = str(exc).encode("utf-8")
            error = exc

        duration_ms = int((time.time() - start) * 1000)

        # ---- record in AHP (fail-open: never crash the agent) ----------
        _local.in_interceptor = True
        try:
            action = create_action_from_http(
                method=method,
                url=url_str,
                request_body=request_body if isinstance(request_body, bytes) else b"",
                response_body=response_body,
                status_code=status_code,
                duration_ms=duration_ms,
            )
            if _recorder is None:
                raise RuntimeError("No recorder attached; call install_http_interceptor(recorder) first")
            _recorder.safe_record(
                tool_name=action.tool_name,
                parameters=request_body if isinstance(request_body, bytes) else b"",
                result=response_body,
                protocol=action.protocol,
                action_type=action.action_type,
                target_entity=url_str,
                model_id=action.model_id,
                input_token_count=action.input_token_count,
                output_token_count=action.output_token_count,
            )
        except Exception:
            pass  # Fail-open: never crash the agent
        finally:
            _local.in_interceptor = False

        # ---- propagate to caller ----------------------------------------
        if error is not None:
            raise error

        return wrapped

    # Perform the actual monkey-patch (under lock to prevent concurrent install race).
    with _install_lock:
        urllib.request.urlopen = _intercepted_urlopen  # type: ignore[assignment]


def uninstall_http_interceptor() -> None:
    """Remove the HTTP interceptor and restore the original ``urlopen``."""
    global _original_urlopen, _recorder

    with _install_lock:
        if _original_urlopen is not None:
            urllib.request.urlopen = _original_urlopen  # type: ignore[assignment]
            _original_urlopen = None
            _recorder = None
