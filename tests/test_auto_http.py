"""Tests for the transparent HTTP interceptor (auto_http).

Spins up a real local HTTP server per test, installs the interceptor,
and verifies that ordinary urllib calls are captured by AHP without any
explicit instrumentation.

Requires Python >= 3.9.
"""

from __future__ import annotations

import http.server
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from typing import Any

from ahp.core.chain import ChainReader, parse_action_payload, parse_envelope
from ahp.core.records import RecordType
from ahp.core.types import ActionType, Protocol
from ahp.core.verify import verify_chain
from ahp.interceptors.http_auto import (
    install_http_interceptor,
    uninstall_http_interceptor,
)
from ahp.recorder import AHPRecorder

# ---------------------------------------------------------------------------
# Helpers: minimal HTTP server
# ---------------------------------------------------------------------------


class _TestHandler(http.server.BaseHTTPRequestHandler):
    """Simple handler that echoes back a known body or returns errors."""

    # Class-level controls (set before each test as needed).
    response_code = 200
    response_body = b"OK"

    def do_GET(self) -> None:
        self.send_response(self.__class__.response_code)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(self.__class__.response_body)

    def do_POST(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)
        self.send_response(self.__class__.response_code)
        self.send_header("Content-Type", "application/octet-stream")
        self.end_headers()
        # Echo the POST body back.
        self.wfile.write(post_data)

    def log_message(self, format: str, *args: Any) -> None:
        # Silence the noisy HTTP server logs during tests.
        pass


def _start_server(handler_class: type = _TestHandler):
    """Start a local HTTP server on a random port and return (server, url)."""
    server = http.server.HTTPServer(("127.0.0.1", 0), handler_class)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = "http://127.0.0.1:%d" % port
    return server, base_url


def _make_recorder(chain_path: str) -> AHPRecorder:
    return AHPRecorder(
        agent_name="auto-http-test",
        chain_path=chain_path,
        level=1,
        checkpoint_interval=99999,  # no auto-checkpoint
    )


def _action_records(chain_path: str):
    """Return parsed (envelope, payload) pairs for every ACTION record."""
    reader = ChainReader(chain_path)
    raw_records = reader.read_all()
    results = []
    for raw in raw_records:
        env = parse_envelope(raw)
        if env["record_type"] == RecordType.ACTION:
            payload = parse_action_payload(env["payload_bytes"])
            results.append((env, payload))
    return results


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestTransparentCapture(unittest.TestCase):
    """Install interceptor, make a plain urlopen call, verify it was recorded."""

    def setUp(self) -> None:
        _TestHandler.response_code = 200
        _TestHandler.response_body = b"hello from test server"
        self.server, self.base_url = _start_server()
        self.tmpdir = tempfile.mkdtemp(prefix="ahp_autohttp_")
        self.chain_path = os.path.join(self.tmpdir, "capture.ahp")
        self.recorder = _make_recorder(self.chain_path)
        install_http_interceptor(self.recorder)

    def tearDown(self) -> None:
        uninstall_http_interceptor()
        self.server.shutdown()

    def test_transparent_capture(self) -> None:
        # Plain urllib call -- no AHP code visible here.
        resp = urllib.request.urlopen(self.base_url + "/data")
        body = resp.read()
        self.assertEqual(body, b"hello from test server")

        # Verify AHP captured it.
        actions = _action_records(self.chain_path)
        self.assertGreaterEqual(len(actions), 1, "No action records captured")

        _, payload = actions[-1]
        self.assertEqual(payload["action_type"], ActionType.TOOL_CALL)
        self.assertEqual(payload["protocol"], Protocol.HTTP)
        self.assertIn("/data", payload["target_entity"])


class TestPostRequest(unittest.TestCase):
    """POST with data is captured and params are recorded."""

    def setUp(self) -> None:
        _TestHandler.response_code = 200
        _TestHandler.response_body = b""  # echo mode for POST
        self.server, self.base_url = _start_server()
        self.tmpdir = tempfile.mkdtemp(prefix="ahp_autohttp_")
        self.chain_path = os.path.join(self.tmpdir, "post.ahp")
        self.recorder = _make_recorder(self.chain_path)
        install_http_interceptor(self.recorder)

    def tearDown(self) -> None:
        uninstall_http_interceptor()
        self.server.shutdown()

    def test_post_request(self) -> None:
        post_data = b'{"key": "value"}'
        req = urllib.request.Request(
            self.base_url + "/submit",
            data=post_data,
            method="POST",
        )
        resp = urllib.request.urlopen(req)
        echoed = resp.read()
        # Server echoes POST body back.
        self.assertEqual(echoed, post_data)

        actions = _action_records(self.chain_path)
        self.assertGreaterEqual(len(actions), 1)
        _, payload = actions[-1]
        self.assertIn("/submit", payload["target_entity"])


class TestErrorCaptured(unittest.TestCase):
    """Server returns 500; verify error is recorded but exception still raised."""

    def setUp(self) -> None:
        _TestHandler.response_code = 500
        _TestHandler.response_body = b"Internal Server Error"
        self.server, self.base_url = _start_server()
        self.tmpdir = tempfile.mkdtemp(prefix="ahp_autohttp_")
        self.chain_path = os.path.join(self.tmpdir, "error.ahp")
        self.recorder = _make_recorder(self.chain_path)
        install_http_interceptor(self.recorder)

    def tearDown(self) -> None:
        uninstall_http_interceptor()
        self.server.shutdown()

    def test_error_captured(self) -> None:
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(self.base_url + "/fail")

        self.assertEqual(ctx.exception.code, 500)

        # AHP should still have captured the action.
        actions = _action_records(self.chain_path)
        self.assertGreaterEqual(len(actions), 1)
        _, payload = actions[-1]
        self.assertIn("/fail", payload["target_entity"])


class TestUninstall(unittest.TestCase):
    """Install then uninstall; verify calls are no longer captured."""

    def setUp(self) -> None:
        _TestHandler.response_code = 200
        _TestHandler.response_body = b"uninstall-test"
        self.server, self.base_url = _start_server()
        self.tmpdir = tempfile.mkdtemp(prefix="ahp_autohttp_")
        self.chain_path = os.path.join(self.tmpdir, "uninstall.ahp")
        self.recorder = _make_recorder(self.chain_path)

    def tearDown(self) -> None:
        # Ensure clean state even if test fails.
        uninstall_http_interceptor()
        self.server.shutdown()

    def test_uninstall(self) -> None:
        install_http_interceptor(self.recorder)

        # First call -- should be captured.
        urllib.request.urlopen(self.base_url + "/before")
        actions_before = _action_records(self.chain_path)
        self.assertGreaterEqual(len(actions_before), 1)

        count_before = len(actions_before)

        uninstall_http_interceptor()

        # Second call -- should NOT be captured.
        urllib.request.urlopen(self.base_url + "/after")
        actions_after = _action_records(self.chain_path)
        self.assertEqual(len(actions_after), count_before)


class TestResponseStillReadable(unittest.TestCase):
    """After interception, the caller can still read() the response body."""

    def setUp(self) -> None:
        _TestHandler.response_code = 200
        _TestHandler.response_body = b"A" * 4096  # Non-trivial body
        self.server, self.base_url = _start_server()
        self.tmpdir = tempfile.mkdtemp(prefix="ahp_autohttp_")
        self.chain_path = os.path.join(self.tmpdir, "readable.ahp")
        self.recorder = _make_recorder(self.chain_path)
        install_http_interceptor(self.recorder)

    def tearDown(self) -> None:
        uninstall_http_interceptor()
        self.server.shutdown()

    def test_response_still_readable(self) -> None:
        resp = urllib.request.urlopen(self.base_url + "/big")
        # Read in chunks to test partial read support.
        chunk1 = resp.read(100)
        chunk2 = resp.read()
        full = chunk1 + chunk2
        self.assertEqual(full, b"A" * 4096)

    def test_response_attributes(self) -> None:
        resp = urllib.request.urlopen(self.base_url + "/attrs")
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getcode(), 200)
        self.assertIn("127.0.0.1", resp.geturl())
        self.assertIsNotNone(resp.info())
        resp.read()


class TestContextManager(unittest.TestCase):
    """Verify ``with urlopen(url) as resp: data = resp.read()`` still works."""

    def setUp(self) -> None:
        _TestHandler.response_code = 200
        _TestHandler.response_body = b"context-manager-body"
        self.server, self.base_url = _start_server()
        self.tmpdir = tempfile.mkdtemp(prefix="ahp_autohttp_")
        self.chain_path = os.path.join(self.tmpdir, "ctxmgr.ahp")
        self.recorder = _make_recorder(self.chain_path)
        install_http_interceptor(self.recorder)

    def tearDown(self) -> None:
        uninstall_http_interceptor()
        self.server.shutdown()

    def test_context_manager(self) -> None:
        with urllib.request.urlopen(self.base_url + "/cm") as resp:
            data = resp.read()
        self.assertEqual(data, b"context-manager-body")

        # Verify AHP still captured it.
        actions = _action_records(self.chain_path)
        self.assertGreaterEqual(len(actions), 1)


class TestChainIntegrity(unittest.TestCase):
    """The chain produced after intercepted calls must pass full verification."""

    def setUp(self) -> None:
        _TestHandler.response_code = 200
        _TestHandler.response_body = b"integrity-check"
        self.server, self.base_url = _start_server()
        self.tmpdir = tempfile.mkdtemp(prefix="ahp_autohttp_")
        self.chain_path = os.path.join(self.tmpdir, "integrity.ahp")
        self.recorder = _make_recorder(self.chain_path)
        install_http_interceptor(self.recorder)

    def tearDown(self) -> None:
        uninstall_http_interceptor()
        self.server.shutdown()

    def test_chain_integrity(self) -> None:
        for i in range(5):
            urllib.request.urlopen(self.base_url + "/req%d" % i).read()

        result = verify_chain(self.chain_path)
        self.assertTrue(result.valid, "Chain invalid: %s" % getattr(result, "error", ""))


if __name__ == "__main__":
    unittest.main()
