"""REAL gRPC test — actual gRPC server, actual gRPC client, AHP interceptor.

Uses grpcio's generic handler (no protoc compilation needed).
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
import unittest
from concurrent import futures
from typing import Any

import grpc

from ahp.core.types import RecordType, ResultStatus, Protocol, ActionType
from ahp.core.records import ActionPayload, BootPayload, Authorization
from ahp.core.chain import ChainWriter, ChainReader, parse_envelope, parse_action_payload
from ahp.core.verify import verify_chain
from ahp.core.json_format import record_to_json
from ahp.core.uuid7 import uuid7
from ahp.interceptors.grpc import AHPClientInterceptor


# ================================================================
# Real gRPC service (no .proto compilation needed)
# ================================================================

def _echo_handler(request: bytes, context: grpc.ServicerContext) -> bytes:
    """Simple echo handler — returns the request with a prefix."""
    return b'ECHO:' + request


def _add_handler(request: bytes, context: grpc.ServicerContext) -> bytes:
    """Add handler — parses JSON, adds numbers, returns result."""
    try:
        data = json.loads(request)
        result = data.get('a', 0) + data.get('b', 0)
        return json.dumps({"sum": result}).encode()
    except Exception as e:
        context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
        context.set_details(str(e))
        return b''


def _fail_handler(request: bytes, context: grpc.ServicerContext) -> bytes:
    """Handler that always fails."""
    context.set_code(grpc.StatusCode.INTERNAL)
    context.set_details("Intentional failure for testing")
    raise Exception("Intentional failure")


def _create_generic_server(port: int = 0) -> tuple:
    """Create a gRPC server with generic handlers (no proto needed).

    Returns (server, port).
    """
    handlers = {
        '/test.TestService/Echo': grpc.unary_unary_rpc_method_handler(_echo_handler),
        '/test.TestService/Add': grpc.unary_unary_rpc_method_handler(_add_handler),
        '/test.TestService/Fail': grpc.unary_unary_rpc_method_handler(_fail_handler),
    }

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
    server.add_generic_rpc_handlers([GenericHandler(handlers)])

    actual_port = server.add_insecure_port(f'localhost:{port}')
    server.start()

    return server, actual_port


class GenericHandler(grpc.GenericRpcHandler):
    """Generic gRPC handler that routes methods without proto stubs."""

    def __init__(self, handlers: dict):
        self._handlers = handlers

    def service(self, handler_call_details: grpc.HandlerCallDetails):
        method = handler_call_details.method
        return self._handlers.get(method)


class TestRealGRPC(unittest.TestCase):
    """Test AHP gRPC interceptor with REAL gRPC server and client."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.chain_path = os.path.join(self.tmpdir, "grpc_real.ahp")
        self.server, self.port = _create_generic_server()

    def tearDown(self):
        self.server.stop(grace=1)

    def _make_channel(self, writer: ChainWriter) -> grpc.Channel:
        """Create intercepted gRPC channel."""
        base_channel = grpc.insecure_channel(f'localhost:{self.port}')
        interceptor = AHPClientInterceptor(writer)
        return grpc.intercept_channel(base_channel, interceptor)

    def test_real_grpc_echo(self):
        """Make a REAL gRPC call. Verify AHP records it with protocol=GRPC."""
        writer = ChainWriter(self.chain_path)
        channel = self._make_channel(writer)

        # Make REAL gRPC call
        response = channel.unary_unary(
            '/test.TestService/Echo',
            request_serializer=None,
            response_deserializer=None,
        )(b'Hello gRPC')

        # Verify real response
        self.assertEqual(response, b'ECHO:Hello gRPC')

        # Verify AHP recorded it
        reader = ChainReader(self.chain_path)
        records = reader.read_all()
        self.assertEqual(len(records), 1)

        j = record_to_json(records[0])
        self.assertEqual(j['payload']['protocol'], 'GRPC')
        self.assertEqual(j['payload']['tool_name'], 'test.TestService/Echo')
        self.assertEqual(j['payload']['action_type'], 'TOOL_CALL')
        self.assertEqual(j['payload']['result_status'], 'SUCCESS')
        self.assertGreaterEqual(j['payload']['response_time_ms'], 0)  # localhost gRPC can be sub-ms

        # Hashes are real (computed from actual request/response)
        self.assertNotEqual(j['payload']['parameters_hash'], '00' * 16)
        self.assertNotEqual(j['payload']['result_hash'], '00' * 16)

        # Chain valid
        self.assertTrue(verify_chain(self.chain_path).valid)

        channel.close()

    def test_real_grpc_add(self):
        """Real gRPC call with JSON payload."""
        writer = ChainWriter(self.chain_path)
        channel = self._make_channel(writer)

        request = json.dumps({"a": 17, "b": 25}).encode()
        response = channel.unary_unary(
            '/test.TestService/Add',
            request_serializer=None,
            response_deserializer=None,
        )(request)

        result = json.loads(response)
        self.assertEqual(result['sum'], 42)

        j = record_to_json(ChainReader(self.chain_path).read_all()[0])
        self.assertEqual(j['payload']['protocol'], 'GRPC')
        self.assertEqual(j['payload']['tool_name'], 'test.TestService/Add')

        # Verify hash matches actual request
        expected_hash = hashlib.sha256(request).digest()[:16].hex()
        self.assertEqual(j['payload']['parameters_hash'], expected_hash)

        channel.close()

    def test_real_grpc_failure(self):
        """Real gRPC call that fails — verify error recorded."""
        writer = ChainWriter(self.chain_path)
        channel = self._make_channel(writer)

        try:
            channel.unary_unary(
                '/test.TestService/Fail',
                request_serializer=None,
                response_deserializer=None,
            )(b'please fail')
            self.fail("Expected gRPC error")
        except grpc.RpcError as e:
            self.assertEqual(e.code(), grpc.StatusCode.INTERNAL)

        # AHP still recorded the failed call
        reader = ChainReader(self.chain_path)
        records = reader.read_all()
        self.assertEqual(len(records), 1)

        j = record_to_json(records[0])
        self.assertEqual(j['payload']['protocol'], 'GRPC')
        self.assertEqual(j['payload']['result_status'], 'ERROR')

        channel.close()

    def test_multiple_grpc_calls_chained(self):
        """Multiple real gRPC calls — verify hash chain integrity."""
        writer = ChainWriter(self.chain_path)
        channel = self._make_channel(writer)

        for i in range(5):
            response = channel.unary_unary(
                '/test.TestService/Echo',
                request_serializer=None,
                response_deserializer=None,
            )(f'call {i}'.encode())
            self.assertIn(b'ECHO:', response)

        result = verify_chain(self.chain_path)
        self.assertTrue(result.valid)
        self.assertEqual(result.records_checked, 5)

        channel.close()

    def test_grpc_hash_determinism(self):
        """Same gRPC request should produce same parameters_hash."""
        writer = ChainWriter(self.chain_path)
        channel = self._make_channel(writer)

        # Same request twice
        for _ in range(2):
            channel.unary_unary(
                '/test.TestService/Echo',
                request_serializer=None,
                response_deserializer=None,
            )(b'deterministic')

        records = ChainReader(self.chain_path).read_all()
        j0 = record_to_json(records[0])
        j1 = record_to_json(records[1])

        # Same request → same parameters_hash
        self.assertEqual(j0['payload']['parameters_hash'], j1['payload']['parameters_hash'])
        # Same response → same result_hash
        self.assertEqual(j0['payload']['result_hash'], j1['payload']['result_hash'])

        channel.close()


if __name__ == '__main__':
    unittest.main()
