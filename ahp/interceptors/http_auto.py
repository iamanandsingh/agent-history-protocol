"""Transparent HTTP interceptor — auto-captures HTTP calls across libraries.

When activated, HTTP calls made via ``urllib.request``, ``requests``, and
``httpx`` are automatically captured and recorded in AHP. No code changes
needed in the agent.

Supported libraries (patched automatically if installed):
- ``urllib.request.urlopen`` (stdlib)
- ``requests.Session.send`` (covers requests.get/post/etc.)
- ``httpx.Client.send`` and ``httpx.AsyncClient.send``

Usage:
    from ahp.interceptors.http_auto import install_http_interceptor

    recorder = AHPRecorder(agent_name="my-agent")
    install_http_interceptor(recorder)

    # ALL HTTP calls via supported libraries are now recorded:
    requests.get("https://api.example.com/data")
    httpx.get("https://api.example.com/data")
    urlopen("https://api.example.com/data")
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
_original_requests_send = None  # type: Optional[Any]
_original_httpx_send = None  # type: Optional[Any]
_original_httpx_async_send = None  # type: Optional[Any]
_recorder = None  # type: Optional[Any]
_install_lock = threading.Lock()

# Per-thread reentrancy guard: prevents the witness client's own HTTP calls
# (made during AHP recording) from being intercepted and recorded again.
_local = threading.local()

# The sentinel that urllib.request.urlopen uses for the default timeout.
_GLOBAL_DEFAULT_TIMEOUT = socket._GLOBAL_DEFAULT_TIMEOUT  # type: ignore[attr-defined]


def _record_http_call(
    method: str,
    url: str,
    request_body: bytes,
    response_body: bytes,
    status_code: int,
    duration_ms: int,
) -> None:
    """Record an HTTP call in AHP (fail-open). Shared by all interceptors."""
    _local.in_interceptor = True
    try:
        action = create_action_from_http(
            method=method,
            url=url,
            request_body=request_body,
            response_body=response_body,
            status_code=status_code,
            duration_ms=duration_ms,
        )
        rec = _recorder
        if rec is None:
            return
        rec.safe_record(
            tool_name=action.tool_name,
            parameters=request_body,
            result=response_body,
            protocol=action.protocol,
            action_type=action.action_type,
            result_status=action.result_status,
            response_time_ms=action.response_time_ms,
            target_entity=url,
            model_id=action.model_id,
            input_token_count=action.input_token_count,
            output_token_count=action.output_token_count,
        )
    except Exception:
        pass  # Fail-open: never crash the agent
    finally:
        _local.in_interceptor = False


# ---------------------------------------------------------------------------
# urllib.request interceptor
# ---------------------------------------------------------------------------


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
        self.status = original.status
        self.headers = original.headers
        self.url = original.url
        self.code = original.code
        self.reason = getattr(original, "reason", "")
        self.msg = getattr(original, "msg", "")
        self.length = len(body)

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

    def __enter__(self) -> "_ReadableResponse":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

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

    def __iter__(self):  # type: ignore[override]
        return iter(self._stream)


def _make_urllib_interceptor() -> Any:
    """Create the urllib.request.urlopen replacement."""

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
        # Reentrancy guard
        if getattr(_local, "in_interceptor", False):
            orig = _original_urlopen
            if orig is None:
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
            return orig(url, data=data, **kw)

        # Extract request metadata
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

        # Build kwargs
        kwargs = {}  # type: dict[str, Any]
        if timeout is not _GLOBAL_DEFAULT_TIMEOUT:
            kwargs["timeout"] = timeout
        if cafile is not None:
            kwargs["cafile"] = cafile
        if capath is not None:
            kwargs["capath"] = capath
        if context is not None:
            kwargs["context"] = context

        # Execute real HTTP call
        start = time.time()
        response_body = b""
        status_code = 0
        error = None  # type: Optional[Exception]
        wrapped = None  # type: Optional[_ReadableResponse]

        try:
            orig = _original_urlopen
            if orig is None:
                raise RuntimeError("HTTP interceptor not installed")
            response = orig(url, data=data, **kwargs)
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

        # Record
        req_bytes = request_body if isinstance(request_body, bytes) else b""
        _record_http_call(method, url_str, req_bytes, response_body, status_code, duration_ms)

        if error is not None:
            raise error
        return wrapped

    return _intercepted_urlopen


# ---------------------------------------------------------------------------
# requests interceptor
# ---------------------------------------------------------------------------


def _make_requests_interceptor(original_send: Any) -> Any:
    """Create the requests.Session.send replacement."""

    def _intercepted_send(self: Any, request: Any, **kwargs: Any) -> Any:
        # Reentrancy guard
        if getattr(_local, "in_interceptor", False):
            return original_send(self, request, **kwargs)

        url_str = str(request.url)
        method = request.method or "GET"
        request_body = request.body or b""
        if isinstance(request_body, str):
            request_body = request_body.encode("utf-8")

        start = time.time()
        response = None

        try:
            response = original_send(self, request, **kwargs)
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            _record_http_call(method, url_str, request_body, str(exc).encode("utf-8"), 0, duration_ms)
            raise

        duration_ms = int((time.time() - start) * 1000)
        response_body = response.content if response is not None else b""
        status_code = response.status_code if response is not None else 0

        _record_http_call(method, url_str, request_body, response_body, status_code, duration_ms)

        return response

    return _intercepted_send


# ---------------------------------------------------------------------------
# httpx interceptor (sync + async)
# ---------------------------------------------------------------------------


def _make_httpx_interceptor(original_send: Any) -> Any:
    """Create the httpx.Client.send replacement."""

    def _intercepted_send(self: Any, request: Any, **kwargs: Any) -> Any:
        # Reentrancy guard
        if getattr(_local, "in_interceptor", False):
            return original_send(self, request, **kwargs)

        url_str = str(request.url)
        method = str(request.method)
        request_body = request.content or b""
        if isinstance(request_body, str):
            request_body = request_body.encode("utf-8")

        start = time.time()

        try:
            response = original_send(self, request, **kwargs)
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            _record_http_call(method, url_str, request_body, str(exc).encode("utf-8"), 0, duration_ms)
            raise

        duration_ms = int((time.time() - start) * 1000)
        # httpx streams by default; read() to get the body for hashing
        try:
            response.read()
        except Exception:
            pass
        response_body = response.content if hasattr(response, "content") else b""
        status_code = response.status_code

        _record_http_call(method, url_str, request_body, response_body, status_code, duration_ms)

        return response

    return _intercepted_send


def _make_httpx_async_interceptor(original_send: Any) -> Any:
    """Create the httpx.AsyncClient.send replacement."""

    async def _intercepted_send(self: Any, request: Any, **kwargs: Any) -> Any:
        # Reentrancy guard
        if getattr(_local, "in_interceptor", False):
            return await original_send(self, request, **kwargs)

        url_str = str(request.url)
        method = str(request.method)
        request_body = request.content or b""
        if isinstance(request_body, str):
            request_body = request_body.encode("utf-8")

        start = time.time()

        try:
            response = await original_send(self, request, **kwargs)
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            _record_http_call(method, url_str, request_body, str(exc).encode("utf-8"), 0, duration_ms)
            raise

        duration_ms = int((time.time() - start) * 1000)
        try:
            await response.aread()
        except Exception:
            pass
        response_body = response.content if hasattr(response, "content") else b""
        status_code = response.status_code

        _record_http_call(method, url_str, request_body, response_body, status_code, duration_ms)

        return response

    return _intercepted_send


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def install_http_interceptor(recorder: Any) -> None:
    """Install transparent HTTP interceptors for all available libraries.

    Patches ``urllib.request``, ``requests``, and ``httpx`` (if installed).
    Calling this more than once (without uninstalling first) is a no-op.
    """
    global _original_urlopen, _original_requests_send, _original_httpx_send
    global _original_httpx_async_send, _recorder

    with _install_lock:
        if _original_urlopen is not None:
            return  # Already installed

        _recorder = recorder

        # 1. urllib (always available)
        _original_urlopen = urllib.request.urlopen
        urllib.request.urlopen = _make_urllib_interceptor()  # type: ignore[assignment]
        logger.debug("Installed urllib.request interceptor")

        # 2. requests (if installed)
        try:
            import requests

            _original_requests_send = requests.Session.send
            requests.Session.send = _make_requests_interceptor(_original_requests_send)  # type: ignore[assignment]
            logger.debug("Installed requests interceptor")
        except ImportError:
            pass

        # 3. httpx (if installed)
        try:
            import httpx

            _original_httpx_send = httpx.Client.send
            httpx.Client.send = _make_httpx_interceptor(_original_httpx_send)  # type: ignore[assignment]
            logger.debug("Installed httpx.Client interceptor")

            _original_httpx_async_send = httpx.AsyncClient.send
            httpx.AsyncClient.send = _make_httpx_async_interceptor(_original_httpx_async_send)  # type: ignore[assignment]
            logger.debug("Installed httpx.AsyncClient interceptor")
        except ImportError:
            pass


def uninstall_http_interceptor() -> None:
    """Remove all HTTP interceptors and restore original methods."""
    global _original_urlopen, _original_requests_send, _original_httpx_send
    global _original_httpx_async_send, _recorder

    with _install_lock:
        if _original_urlopen is not None:
            urllib.request.urlopen = _original_urlopen  # type: ignore[assignment]
            _original_urlopen = None
            logger.debug("Uninstalled urllib.request interceptor")

        if _original_requests_send is not None:
            try:
                import requests

                requests.Session.send = _original_requests_send  # type: ignore[assignment]
            except ImportError:
                pass
            _original_requests_send = None
            logger.debug("Uninstalled requests interceptor")

        if _original_httpx_send is not None:
            try:
                import httpx

                httpx.Client.send = _original_httpx_send  # type: ignore[assignment]
            except ImportError:
                pass
            _original_httpx_send = None
            logger.debug("Uninstalled httpx.Client interceptor")

        if _original_httpx_async_send is not None:
            try:
                import httpx

                httpx.AsyncClient.send = _original_httpx_async_send  # type: ignore[assignment]
            except ImportError:
                pass
            _original_httpx_async_send = None
            logger.debug("Uninstalled httpx.AsyncClient interceptor")

        _recorder = None
