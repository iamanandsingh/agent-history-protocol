"""Async AHPRecorder — non-blocking recording for asyncio agent frameworks.

Usage:
    recorder = AsyncAHPRecorder(agent_name="my-agent")
    await recorder.start()

    await recorder.record_action(
        tool_name="search", parameters=b'...', result=b'...',
    )

    await recorder.stop()
"""

from __future__ import annotations

import logging
from typing import Any, Callable, List, Optional

from ahp._base_recorder import RecorderBase
from ahp.config import AHPConfig
from ahp.core.async_chain import AsyncChainWriter
from ahp.core.records import (
    ActionPayload,
    Authorization,
    GapPayload,
    Record,
)
from ahp.core.types import (
    ActionType,
    AuthorizationType,
    GapReason,
    Protocol,
    ResultStatus,
)

logger = logging.getLogger("ahp.recorder")


class AsyncAHPRecorder(RecorderBase):
    """Async version of AHPRecorder for asyncio agent frameworks.

    Wires: async chain writer + evidence + PII filters + signing + witness.
    Fail-open: never crashes the agent.
    """

    def __init__(
        self,
        agent_name: str = "",
        chain_path: Optional[str] = None,
        level: int = 1,
        config: Optional[AHPConfig] = None,
        evidence_path: Optional[str] = None,
        filter_presets: Optional[List[str]] = None,
        checkpoint_interval: int = 1000,
        witness_endpoints: Optional[List[str]] = None,
        on_record_written: Optional[Callable[[Record], None]] = None,
        on_error: Optional[Callable[[Exception, str], None]] = None,
    ):

        agent_name = agent_name or (config.agent_name if config else "") or "ahp-agent"
        path = chain_path or f"{agent_name}.ahp"

        # ---- shared initialization (config, filters, evidence, signing) ----
        self._init_shared_components(
            agent_name=agent_name,
            level=level,
            config=config,
            evidence_path=evidence_path,
            filter_presets=filter_presets,
            custom_filters=None,
            checkpoint_interval=checkpoint_interval,
            witness_endpoints=witness_endpoints,
            on_record_written=on_record_written,
            on_error=on_error,
        )

        self.writer = AsyncChainWriter(path)
        # Alias for base class structured logging
        self._chain = self.writer
        self._started = False

    async def start(self) -> None:
        """Start the async writer and emit boot records."""
        await self.writer.start()
        self._started = True

        # Boot record (using shared payload construction)
        boot_payload = self._build_boot_payload()
        record = await self.writer.write_record(boot_payload)
        self._track_record(record)

        # Key genesis (Level 2+)
        key_payload = self._build_key_genesis_payload()
        if key_payload is not None:
            record = await self.writer.write_record(key_payload)
            self._track_record(record)

    async def stop(self) -> None:
        """Flush and stop the async writer."""
        if self._started:
            await self.writer.stop()
            self._started = False

    async def close(self) -> None:
        """Stop the writer and release resources."""
        await self.stop()

    async def __aenter__(self) -> "AsyncAHPRecorder":
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    async def record_action(
        self,
        tool_name: str = "",
        parameters: bytes = b"",
        result: bytes = b"",
        protocol: Protocol = Protocol.CUSTOM,
        action_type: ActionType = ActionType.TOOL_CALL,
        result_status: ResultStatus = ResultStatus.SUCCESS,
        target_entity: str = "",
        model_id: str = "",
        input_token_count: int = 0,
        output_token_count: int = 0,
        cache_read_tokens: int = 0,
        cache_creation_tokens: int = 0,
        reasoning_tokens: int = 0,
        cost_nano_usd: Optional[int] = None,
        provider: str = "",
        authorization: Optional[Authorization] = None,
        parent_action_id: Optional[bytes] = None,
        session_id: Optional[bytes] = None,
        response_time_ms: int = 0,
    ) -> Optional[Record]:
        """Record an action. Returns the Record or None on failure."""
        # Flush pending gap
        if self._pending_gap:
            await self._emit_pending_gap()

        # Auto-estimate cost if not provided and we have model + tokens
        if cost_nano_usd is None and model_id and (input_token_count > 0 or output_token_count > 0):
            from ahp.core.pricing import estimate_cost_nano

            cost_nano_usd = estimate_cost_nano(model_id, input_token_count, output_token_count)
        if cost_nano_usd is None:
            cost_nano_usd = 0

        # PII filtering (shared logic from base)
        param_hash, result_hash, filtered_params, filtered_result, redacted = self._filter_action_payloads(
            parameters, result
        )

        # Evidence (shared logic from base)
        self._store_evidence(filtered_params, filtered_result, param_hash)

        payload = ActionPayload(
            parent_action_id=parent_action_id or b"\x00" * 16,
            tool_name=tool_name,
            parameters_hash=param_hash,
            result_hash=result_hash,
            result_status=result_status,
            response_time_ms=response_time_ms,
            protocol=protocol,
            action_type=action_type,
            target_entity=target_entity,
            redacted=redacted,
            model_id=model_id,
            input_token_count=input_token_count,
            output_token_count=output_token_count,
            cache_read_tokens=cache_read_tokens,
            cache_creation_tokens=cache_creation_tokens,
            reasoning_tokens=reasoning_tokens,
            cost_nano_usd=cost_nano_usd,
            provider=provider,
            authorization=authorization or Authorization(type=AuthorizationType.AUTH_NONE),
        )

        record = await self.writer.write_record(payload, session_id=session_id)

        # Track for checkpoints (shared logic from base)
        self._track_record(record)

        # Auto-checkpoint
        if self._records_since_checkpoint >= self._checkpoint_interval:
            await self.emit_checkpoint()

        return record

    async def record_inference(
        self,
        tool_name: str = "",
        parameters: bytes = b"",
        result: bytes = b"",
        model_id: str = "",
        input_token_count: int = 0,
        output_token_count: int = 0,
        cache_read_tokens: int = 0,
        cache_creation_tokens: int = 0,
        reasoning_tokens: int = 0,
        cost_nano_usd: Optional[int] = None,
        provider: str = "",
        response_time_ms: int = 0,
        **kwargs: Any,
    ) -> Optional[Record]:
        """Record an LLM inference call."""
        return await self.record_action(
            tool_name=tool_name,
            parameters=parameters,
            result=result,
            protocol=Protocol.HTTP,
            action_type=ActionType.INFERENCE,
            model_id=model_id,
            input_token_count=input_token_count,
            output_token_count=output_token_count,
            cache_read_tokens=cache_read_tokens,
            cache_creation_tokens=cache_creation_tokens,
            reasoning_tokens=reasoning_tokens,
            cost_nano_usd=cost_nano_usd,
            provider=provider,
            response_time_ms=response_time_ms,
            **kwargs,
        )

    async def emit_checkpoint(self) -> None:
        """Emit a BatchCheckpoint record."""
        # Build checkpoint payload (shared logic from base)
        payload = self._build_checkpoint_payload(
            record_count=self.writer.record_count + 1,
            gap_count=self.writer.gap_count,
            chain_hash=self.writer.prev_hash,
        )

        await self.writer.write_record(payload)

        # Reset counters (shared logic from base)
        self._reset_checkpoint_counters()

    async def safe_record(self, **kwargs: Any) -> Optional[Record]:
        """Fail-open wrapper. Never crashes the agent."""
        try:
            return await self.record_action(**kwargs)
        except Exception as exc:
            if not self._pending_gap:
                self._gap_first_lost_seq = self.writer.sequence + 1
            self._pending_gap = True
            self._gap_detail = str(exc)
            self._log_warning("Async safe_record failed (will emit GapRecord): %s", exc)
            self._fire_error_callback(exc, "async_safe_record")
            return None

    async def _emit_pending_gap(self) -> None:
        """Emit a GapRecord for a previously failed recording."""
        try:
            first_lost = self._gap_first_lost_seq
            last_lost = self.writer.sequence
            if first_lost > last_lost:
                last_lost = first_lost
            count = last_lost - first_lost + 1

            await self.writer.write_record(
                GapPayload(
                    first_lost_sequence=first_lost,
                    last_lost_sequence=last_lost,
                    count=count,
                    reason=GapReason.INTERCEPTOR_FAILURE,
                    detail=self._gap_detail,
                )
            )
            self._pending_gap = False
            self._gap_detail = ""
            self._gap_first_lost_seq = 0
        except Exception:
            pass

    @classmethod
    async def from_config(cls, config_path: str, agent_name: str = "") -> "AsyncAHPRecorder":
        """Create from config file and start."""
        from ahp.config import load_config

        config = load_config(config_path, agent_name)
        recorder = cls(agent_name=agent_name, config=config)
        await recorder.start()
        return recorder
