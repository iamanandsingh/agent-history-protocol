"""LangChain integration — BaseCallbackHandler for automatic AHP recording.

Usage:
    from ahp.integrations.langchain import AHPCallbackHandler
    handler = AHPCallbackHandler(chain_writer)
    agent = create_react_agent(llm, tools, callbacks=[handler])
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Optional, Dict, List, Union
from ahp.core.types import ResultStatus, Protocol, ActionType, AuthorizationType
from ahp.core.records import ActionPayload, Authorization
from ahp.core.chain import ChainWriter

try:
    from langchain_core.callbacks import BaseCallbackHandler as _LCBase
except ImportError:
    _LCBase = object  # type: ignore

def _hash16(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()[:16]

class AHPCallbackHandler(_LCBase):
    """LangChain callback handler that records actions to AHP.

    Inherits from langchain_core.callbacks.BaseCallbackHandler when
    langchain-core is installed. Falls back to plain object otherwise.
    """

    def __init__(self, writer: ChainWriter, session_id: Optional[bytes] = None):
        self.writer = writer
        self.session_id = session_id
        self._tool_starts: Dict[str, float] = {}
        self._llm_starts: Dict[str, float] = {}

    def on_tool_start(self, serialized: Dict[str, Any], input_str: str,
                      run_id: Optional[str] = None, **kwargs: Any) -> None:
        key = run_id or str(id(serialized))
        self._tool_starts[key] = time.time()

    def on_tool_end(self, output: str, run_id: Optional[str] = None,
                    **kwargs: Any) -> None:
        key = run_id or 'unknown'
        start = self._tool_starts.pop(key, time.time())
        duration_ms = int((time.time() - start) * 1000)

        tool_name = kwargs.get('name', 'unknown_tool')
        params_bytes = kwargs.get('input_str', '').encode('utf-8') if 'input_str' in kwargs else b'{}'
        result_bytes = output.encode('utf-8') if isinstance(output, str) else str(output).encode('utf-8')

        self.writer.write_record(ActionPayload(
            tool_name=tool_name,
            parameters_hash=_hash16(params_bytes),
            result_hash=_hash16(result_bytes),
            result_status=ResultStatus.SUCCESS,
            response_time_ms=duration_ms,
            protocol=Protocol.HTTP,
            action_type=ActionType.TOOL_CALL,
            authorization=Authorization(type=AuthorizationType.AUTH_NONE),
        ), session_id=self.session_id)

    def on_tool_error(self, error: BaseException, run_id: Optional[str] = None,
                      **kwargs: Any) -> None:
        key = run_id or 'unknown'
        start = self._tool_starts.pop(key, time.time())
        duration_ms = int((time.time() - start) * 1000)

        self.writer.write_record(ActionPayload(
            tool_name=kwargs.get('name', 'unknown_tool'),
            parameters_hash=b'\x00' * 16,
            result_hash=_hash16(str(error).encode('utf-8')),
            result_status=ResultStatus.ERROR,
            response_time_ms=duration_ms,
            protocol=Protocol.HTTP,
            action_type=ActionType.TOOL_CALL,
            authorization=Authorization(type=AuthorizationType.AUTH_NONE),
        ), session_id=self.session_id)

    def on_llm_start(self, serialized: Dict[str, Any], prompts: List[str],
                     run_id: Optional[str] = None, **kwargs: Any) -> None:
        key = run_id or str(id(serialized))
        self._llm_starts[key] = time.time()

    def on_llm_end(self, response: Any, run_id: Optional[str] = None,
                   **kwargs: Any) -> None:
        key = run_id or 'unknown'
        start = self._llm_starts.pop(key, time.time())
        duration_ms = int((time.time() - start) * 1000)

        response_text = str(response)
        model_id = ''
        if hasattr(response, 'llm_output') and response.llm_output:
            model_id = response.llm_output.get('model_name', '')

        self.writer.write_record(ActionPayload(
            tool_name=model_id or 'llm',
            parameters_hash=b'\x00' * 16,
            result_hash=_hash16(response_text.encode('utf-8')),
            result_status=ResultStatus.SUCCESS,
            response_time_ms=duration_ms,
            protocol=Protocol.HTTP,
            action_type=ActionType.INFERENCE,
            model_id=model_id,
            authorization=Authorization(type=AuthorizationType.AUTH_NONE),
        ), session_id=self.session_id)
