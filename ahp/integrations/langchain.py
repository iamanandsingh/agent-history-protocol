"""LangChain integration — BaseCallbackHandler for automatic AHP recording.

Routes all LangChain tool calls and LLM inferences through the full
AHPRecorder pipeline: PII filtering, evidence storage, hash chain,
checkpointing, witness submission, and callback hooks.

Usage:
    from ahp import AHPRecorder
    from ahp.integrations.langchain import AHPCallbackHandler

    recorder = AHPRecorder(agent_name="my-agent", level=2, filter_presets=["pii-us", "credentials"])
    handler = AHPCallbackHandler(recorder)
    agent = create_react_agent(llm, tools, callbacks=[handler])

    # ... run agent ...
    recorder.close()
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

from ahp.core.records import Authorization
from ahp.core.types import ActionType, Protocol, ResultStatus

try:
    from langchain_core.callbacks import BaseCallbackHandler as _LCBase
except ImportError:
    _LCBase = object  # type: ignore


class AHPCallbackHandler(_LCBase):
    """LangChain callback handler that records actions via AHPRecorder.

    Uses the full recorder pipeline including:
    - PII filtering (redacts sensitive data before hashing)
    - Evidence storage (stores raw payloads for audit)
    - Hash chain integrity (tamper-evident recording)
    - Auto-checkpointing (periodic Merkle root + signing)
    - Witness submission (Level 3 external attestation)
    - Callback hooks (on_record_written, on_error)
    - Fail-open (never crashes the LangChain agent)

    Accepts either an AHPRecorder (recommended) or a raw ChainWriter
    (legacy, bypasses PII filtering and evidence storage).
    """

    def __init__(
        self,
        recorder: Any,
        session_id: Optional[bytes] = None,
        authorization: Optional[Authorization] = None,
    ):
        """Initialize the callback handler.

        Args:
            recorder: An AHPRecorder instance (recommended) or a ChainWriter
                (legacy). When an AHPRecorder is used, all features
                (PII filtering, evidence, checkpointing, etc.) are active.
            session_id: Optional session ID override. If None, uses the
                recorder's default session.
            authorization: Optional default authorization for all recorded
                actions. Can be overridden per-action via kwargs.
        """
        self._recorder = recorder
        self._session_id = session_id
        self._default_auth = authorization
        self._tool_starts: Dict[str, float] = {}
        self._tool_inputs: Dict[str, str] = {}
        self._llm_starts: Dict[str, float] = {}
        self._llm_prompts: Dict[str, str] = {}

        # Detect whether we have a full recorder or a raw ChainWriter
        self._has_recorder = hasattr(recorder, "record_action")

    # ------------------------------------------------------------------
    # Tool callbacks
    # ------------------------------------------------------------------

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        run_id: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """Called when a LangChain tool starts execution."""
        key = run_id or str(id(serialized))
        self._tool_starts[key] = time.time()
        self._tool_inputs[key] = input_str

    def on_tool_end(
        self,
        output: str,
        run_id: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """Called when a LangChain tool finishes successfully."""
        key = run_id or "unknown"
        start = self._tool_starts.pop(key, time.time())
        input_str = self._tool_inputs.pop(key, "{}")
        duration_ms = int((time.time() - start) * 1000)

        tool_name = kwargs.get("name", "unknown_tool")
        params_bytes = input_str.encode("utf-8")
        result_bytes = output.encode("utf-8") if isinstance(output, str) else str(output).encode("utf-8")

        if self._has_recorder:
            # Full pipeline: PII filtering, evidence, checkpointing, etc.
            self._recorder.safe_record(
                tool_name=tool_name,
                parameters=params_bytes,
                result=result_bytes,
                protocol=Protocol.HTTP,
                action_type=ActionType.TOOL_CALL,
                result_status=ResultStatus.SUCCESS,
                response_time_ms=duration_ms,
                authorization=self._default_auth,
            )
        else:
            # Legacy: raw ChainWriter (no PII filtering/evidence)
            self._legacy_write_tool(
                tool_name,
                params_bytes,
                result_bytes,
                ResultStatus.SUCCESS,
                duration_ms,
            )

    def on_tool_error(
        self,
        error: BaseException,
        run_id: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """Called when a LangChain tool raises an error."""
        key = run_id or "unknown"
        start = self._tool_starts.pop(key, time.time())
        input_str = self._tool_inputs.pop(key, "{}")
        duration_ms = int((time.time() - start) * 1000)

        tool_name = kwargs.get("name", "unknown_tool")
        params_bytes = input_str.encode("utf-8")
        error_bytes = str(error).encode("utf-8")

        if self._has_recorder:
            self._recorder.safe_record(
                tool_name=tool_name,
                parameters=params_bytes,
                result=error_bytes,
                protocol=Protocol.HTTP,
                action_type=ActionType.TOOL_CALL,
                result_status=ResultStatus.ERROR,
                response_time_ms=duration_ms,
                authorization=self._default_auth,
            )
        else:
            self._legacy_write_tool(
                tool_name,
                params_bytes,
                error_bytes,
                ResultStatus.ERROR,
                duration_ms,
            )

    # ------------------------------------------------------------------
    # LLM callbacks
    # ------------------------------------------------------------------

    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        run_id: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """Called when an LLM call starts."""
        key = run_id or str(id(serialized))
        self._llm_starts[key] = time.time()
        # Store the prompts for evidence recording
        self._llm_prompts[key] = json.dumps(prompts)

    def on_llm_end(
        self,
        response: Any,
        run_id: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """Called when an LLM call finishes."""
        key = run_id or "unknown"
        start = self._llm_starts.pop(key, time.time())
        prompt_json = self._llm_prompts.pop(key, "[]")
        duration_ms = int((time.time() - start) * 1000)

        response_text = str(response)
        model_id = ""
        input_tokens = 0
        output_tokens = 0

        # Extract model info and token counts from LangChain response
        if hasattr(response, "llm_output") and response.llm_output:
            model_id = response.llm_output.get("model_name", "")
            usage = response.llm_output.get("token_usage", {})
            if isinstance(usage, dict):
                input_tokens = usage.get("prompt_tokens", 0)
                output_tokens = usage.get("completion_tokens", 0)

        prompt_bytes = prompt_json.encode("utf-8")
        response_bytes = response_text.encode("utf-8")

        if self._has_recorder:
            # Full pipeline with PII filtering on prompts and responses
            self._recorder.safe_record(
                tool_name=model_id or "llm",
                parameters=prompt_bytes,
                result=response_bytes,
                protocol=Protocol.HTTP,
                action_type=ActionType.INFERENCE,
                result_status=ResultStatus.SUCCESS,
                response_time_ms=duration_ms,
                model_id=model_id,
                input_token_count=input_tokens,
                output_token_count=output_tokens,
                authorization=self._default_auth,
            )
        else:
            self._legacy_write_inference(
                model_id,
                prompt_bytes,
                response_bytes,
                duration_ms,
                input_tokens,
                output_tokens,
            )

    def on_llm_error(
        self,
        error: BaseException,
        run_id: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """Called when an LLM call raises an error."""
        key = run_id or "unknown"
        start = self._llm_starts.pop(key, time.time())
        prompt_json = self._llm_prompts.pop(key, "[]")
        duration_ms = int((time.time() - start) * 1000)

        prompt_bytes = prompt_json.encode("utf-8")
        error_bytes = str(error).encode("utf-8")

        if self._has_recorder:
            self._recorder.safe_record(
                tool_name="llm",
                parameters=prompt_bytes,
                result=error_bytes,
                protocol=Protocol.HTTP,
                action_type=ActionType.INFERENCE,
                result_status=ResultStatus.ERROR,
                response_time_ms=duration_ms,
                authorization=self._default_auth,
            )
        else:
            self._legacy_write_inference(
                "llm",
                prompt_bytes,
                error_bytes,
                duration_ms,
                0,
                0,
            )

    # ------------------------------------------------------------------
    # Chain callbacks (for agent reasoning chains)
    # ------------------------------------------------------------------

    def on_chain_start(
        self,
        serialized: Dict[str, Any],
        inputs: Dict[str, Any],
        run_id: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """Called when a LangChain chain starts. Recorded as a delegation."""
        pass  # Start timing tracked via run_id if needed

    def on_chain_end(
        self,
        outputs: Dict[str, Any],
        run_id: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """Called when a LangChain chain ends."""
        pass  # Chain-level recording is optional; tool/LLM calls are the primary records

    # ------------------------------------------------------------------
    # Legacy support (raw ChainWriter)
    # ------------------------------------------------------------------

    def _legacy_write_tool(
        self,
        tool_name: str,
        params: bytes,
        result: bytes,
        status: ResultStatus,
        duration_ms: int,
    ) -> None:
        """Write a tool action directly to ChainWriter (no PII filtering/evidence)."""
        import hashlib

        from ahp.core.records import ActionPayload, Authorization
        from ahp.core.types import AuthorizationType

        self._recorder.write_record(
            ActionPayload(
                tool_name=tool_name,
                parameters_hash=hashlib.sha256(params).digest()[:16],
                result_hash=hashlib.sha256(result).digest()[:16],
                result_status=status,
                response_time_ms=duration_ms,
                protocol=Protocol.HTTP,
                action_type=ActionType.TOOL_CALL,
                authorization=Authorization(type=AuthorizationType.AUTH_NONE),
            ),
            session_id=self._session_id,
        )

    def _legacy_write_inference(
        self,
        model_id: str,
        params: bytes,
        result: bytes,
        duration_ms: int,
        input_tokens: int,
        output_tokens: int,
    ) -> None:
        """Write an inference action directly to ChainWriter (no PII filtering/evidence)."""
        import hashlib

        from ahp.core.records import ActionPayload, Authorization
        from ahp.core.types import AuthorizationType

        self._recorder.write_record(
            ActionPayload(
                tool_name=model_id or "llm",
                parameters_hash=hashlib.sha256(params).digest()[:16],
                result_hash=hashlib.sha256(result).digest()[:16],
                result_status=ResultStatus.SUCCESS,
                response_time_ms=duration_ms,
                protocol=Protocol.HTTP,
                action_type=ActionType.INFERENCE,
                model_id=model_id,
                input_token_count=input_tokens,
                output_token_count=output_tokens,
                authorization=Authorization(type=AuthorizationType.AUTH_NONE),
            ),
            session_id=self._session_id,
        )
