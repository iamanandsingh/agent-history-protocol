"""gRPC interceptor — captures gRPC calls with AHP recording.

Requires the `grpcio` package. Falls back gracefully if not installed.

Usage (when grpcio is available):
    from ahp.interceptors.grpc import AHPClientInterceptor
    channel = grpc.intercept_channel(
        grpc.insecure_channel('localhost:50051'),
        AHPClientInterceptor(writer)
    )
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Optional, Any, Callable

from ahp.core.types import ResultStatus, Protocol, ActionType, AuthorizationType
from ahp.core.records import ActionPayload, Authorization
from ahp.core.chain import ChainWriter

try:
    import grpc
    HAS_GRPC = True
except ImportError:
    HAS_GRPC = False


def create_action_from_grpc(
    service_name: str,
    method_name: str,
    request_bytes: bytes,
    response_bytes: bytes,
    duration_ms: int,
    success: bool = True,
    metadata: Optional[dict] = None,
) -> ActionPayload:
    """Create an ActionPayload from a gRPC call.

    Works regardless of whether grpcio is installed — just needs the call data.
    """
    params_hash = hashlib.sha256(request_bytes).digest()[:16] if request_bytes else b'\x00' * 16
    result_hash = hashlib.sha256(response_bytes).digest()[:16] if response_bytes else b'\x00' * 16

    return ActionPayload(
        tool_name=f"{service_name}/{method_name}",
        parameters_hash=params_hash,
        result_hash=result_hash,
        result_status=ResultStatus.SUCCESS if success else ResultStatus.ERROR,
        response_time_ms=duration_ms,
        protocol=Protocol.GRPC,
        action_type=ActionType.TOOL_CALL,
        target_entity=service_name,
        authorization=Authorization(type=AuthorizationType.AUTH_NONE),
    )


if HAS_GRPC:
    class AHPClientInterceptor(grpc.UnaryUnaryClientInterceptor):
        """gRPC client interceptor that records every call in AHP.

        Register with:
            channel = grpc.intercept_channel(channel, AHPClientInterceptor(writer))
        """

        def __init__(self, writer: ChainWriter, session_id: Optional[bytes] = None):
            self.writer = writer
            self.session_id = session_id

        def intercept_unary_unary(self, continuation: Callable,
                                  client_call_details: Any,
                                  request: Any) -> Any:
            method = client_call_details.method
            if isinstance(method, bytes):
                method = method.decode('utf-8')

            # Extract service and method name from /package.Service/Method
            parts = method.strip('/').rsplit('/', 1)
            service_name = parts[0] if len(parts) > 1 else ''
            method_name = parts[1] if len(parts) > 1 else parts[0]

            # Serialize request
            if isinstance(request, bytes):
                request_bytes = request
            else:
                try:
                    request_bytes = request.SerializeToString()
                except Exception:
                    request_bytes = str(request).encode()

            start = time.time()
            try:
                response = continuation(client_call_details, request)
                result = response.result()
                duration_ms = int((time.time() - start) * 1000)

                if isinstance(result, bytes):
                    response_bytes = result
                else:
                    try:
                        response_bytes = result.SerializeToString()
                    except Exception:
                        response_bytes = str(result).encode()

                action = create_action_from_grpc(
                    service_name=service_name,
                    method_name=method_name,
                    request_bytes=request_bytes,
                    response_bytes=response_bytes,
                    duration_ms=duration_ms,
                    success=True,
                )
                self.writer.write_record(action, session_id=self.session_id)

                return response

            except grpc.RpcError as e:
                duration_ms = int((time.time() - start) * 1000)
                error_bytes = str(e).encode()

                action = create_action_from_grpc(
                    service_name=service_name,
                    method_name=method_name,
                    request_bytes=request_bytes,
                    response_bytes=error_bytes,
                    duration_ms=duration_ms,
                    success=False,
                )
                self.writer.write_record(action, session_id=self.session_id)
                raise
else:
    class AHPClientInterceptor:
        """Stub when grpcio is not installed."""
        def __init__(self, *args: Any, **kwargs: Any):
            raise ImportError(
                "grpcio is required for gRPC interception. "
                "Install with: pip install grpcio"
            )
