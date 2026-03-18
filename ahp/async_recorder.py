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

import hashlib
import platform
import time
from pathlib import Path
from typing import Optional, List, Dict, Any

from ahp.core.types import (
    RecordType, ResultStatus, Protocol, ActionType,
    AuthorizationType, ChainLevel, FsyncMode,
    ZERO_HASH_16, ZERO_HASH_32,
)
from ahp.core.records import (
    ActionPayload, BootPayload, CheckpointPayload, GapPayload,
    KeyPayload, WitnessPayload,
    Authorization, AuthorizationEntry,
)
from ahp.core.async_chain import AsyncChainWriter
from ahp.core.evidence import EvidenceStore
from ahp.core.filters import FilterPipeline
from ahp.core.signing import generate_keypair, sign, compute_merkle_root, HAS_CRYPTO
from ahp.core.uuid7 import uuid7
from ahp.config import AHPConfig


class AsyncAHPRecorder:
    """Async version of AHPRecorder for asyncio agent frameworks.

    Wires: async chain writer + evidence + PII filters + signing + witness.
    Fail-open: never crashes the agent.
    """

    def __init__(self, agent_name: str = "", chain_path: Optional[str] = None,
                 level: int = 1, config: Optional[AHPConfig] = None,
                 evidence_path: Optional[str] = None,
                 filter_presets: Optional[List[str]] = None,
                 checkpoint_interval: int = 1000,
                 witness_endpoints: Optional[List[str]] = None):

        self.config = config or AHPConfig(
            level=level, agent_name=agent_name,
            checkpoint_interval=checkpoint_interval,
        )

        agent_name = agent_name or self.config.agent_name or "ahp-agent"
        path = chain_path or f"{agent_name}.ahp"

        self.writer = AsyncChainWriter(path)
        self.level = self.config.level
        self.agent_name = agent_name

        # Evidence store
        self.evidence_store = None
        if self.config.evidence_record:
            ep = evidence_path or "evidence"
            self.evidence_store = EvidenceStore(ep)

        # PII filters
        presets = filter_presets or self.config.filter_presets
        self.filter_pipeline = FilterPipeline(presets=presets) if presets else None

        # Signing (Level 2+)
        self.keypair = None
        if self.level >= 2:
            self.keypair = generate_keypair()

        # Witness (Level 3)
        self.witness_endpoints = witness_endpoints or []
        if self.config.witness.enabled:
            self.witness_endpoints = self.config.witness.endpoints

        # Counters
        self._checkpoint_interval = self.config.checkpoint_interval
        self._records_since_checkpoint = 0
        self._record_hashes: List[bytes] = []
        self._pending_gap = False
        self._gap_detail = ""
        self._started = False

    async def start(self) -> None:
        """Start the async writer and emit boot records."""
        await self.writer.start()
        self._started = True

        # Boot record
        await self.writer.write_record(BootPayload(
            sdk_name="ahp-python",
            sdk_version="0.1.0",
            agent_name=self.agent_name,
            runtime=f"python {platform.python_version()}",
            chain_level=ChainLevel(self.level),
            inference_recording=self.config.inference_record,
            inference_evidence=self.config.inference_evidence,
            evidence_recording=self.config.evidence_record,
            authorization_recording=self.config.authorization_record,
            filter_config_hash=self.filter_pipeline.config_hash() if self.filter_pipeline else ZERO_HASH_32,
        ))

        # Key genesis (Level 2+)
        if self.level >= 2 and self.keypair:
            await self.writer.write_record(KeyPayload(
                public_key=self.keypair.public_key_bytes,
                key_id=self.keypair.key_id,
            ))

    async def stop(self) -> None:
        """Flush and stop the async writer."""
        if self._started:
            await self.writer.stop()
            self._started = False

    async def record_action(self, tool_name: str = "",
                            parameters: bytes = b'',
                            result: bytes = b'',
                            protocol: Protocol = Protocol.CUSTOM,
                            action_type: ActionType = ActionType.TOOL_CALL,
                            target_entity: str = "",
                            model_id: str = "",
                            input_token_count: int = 0,
                            output_token_count: int = 0,
                            authorization: Optional[Authorization] = None,
                            parent_action_id: Optional[bytes] = None,
                            session_id: Optional[bytes] = None,
                            response_time_ms: int = 0) -> Optional[Record]:
        """Record an action. Returns the Record or None on failure."""
        # Flush pending gap
        if self._pending_gap:
            await self._emit_pending_gap()

        # PII filtering
        redacted = False
        if self.filter_pipeline:
            params_hash, filtered_params, r1 = self.filter_pipeline.hash_payload(parameters, "parameters")
            result_hash, filtered_result, r2 = self.filter_pipeline.hash_payload(result, "results")
            redacted = r1 or r2
        else:
            params_hash = hashlib.sha256(parameters).digest()[:16] if parameters else ZERO_HASH_16
            result_hash = hashlib.sha256(result).digest()[:16] if result else ZERO_HASH_16
            filtered_params = parameters
            filtered_result = result

        # Evidence
        if self.evidence_store:
            if filtered_params:
                self.evidence_store.store(filtered_params)
            if filtered_result:
                self.evidence_store.store(filtered_result)

        payload = ActionPayload(
            parent_action_id=parent_action_id or b'\x00' * 16,
            tool_name=tool_name,
            parameters_hash=params_hash,
            result_hash=result_hash,
            result_status=ResultStatus.SUCCESS,
            response_time_ms=response_time_ms,
            protocol=protocol,
            action_type=action_type,
            target_entity=target_entity,
            redacted=redacted,
            model_id=model_id,
            input_token_count=input_token_count,
            output_token_count=output_token_count,
            authorization=authorization or Authorization(type=AuthorizationType.AUTH_NONE),
        )

        record = await self.writer.write_record(payload, session_id=session_id)

        # Track for checkpoints
        self._records_since_checkpoint += 1
        if record._stored_bytes:
            self._record_hashes.append(hashlib.sha256(record._stored_bytes).digest())

        # Auto-checkpoint
        if self._records_since_checkpoint >= self._checkpoint_interval:
            await self.emit_checkpoint()

        return record

    async def record_inference(self, tool_name: str = "",
                               parameters: bytes = b'',
                               result: bytes = b'',
                               model_id: str = "",
                               input_token_count: int = 0,
                               output_token_count: int = 0,
                               response_time_ms: int = 0,
                               **kwargs: Any) -> Optional[Record]:
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
            response_time_ms=response_time_ms,
            **kwargs,
        )

    async def emit_checkpoint(self) -> None:
        """Emit a BatchCheckpoint record."""
        merkle_root = ZERO_HASH_32
        sig = b'\x00' * 64
        key_id = ZERO_HASH_32

        if self._record_hashes:
            merkle_root = compute_merkle_root(self._record_hashes)

        if self.level >= 2 and self.keypair and HAS_CRYPTO:
            sig = sign(merkle_root, self.keypair.private_key_bytes)
            key_id = self.keypair.key_id

        await self.writer.write_record(CheckpointPayload(
            record_count=self.writer.record_count + 1,
            gap_count=0,
            chain_hash=self.writer.prev_hash,
            merkle_root=merkle_root,
            signature=sig,
            signing_key_id=key_id,
        ))

        self._records_since_checkpoint = 0
        self._record_hashes = []

    async def safe_record(self, **kwargs: Any) -> Optional[Record]:
        """Fail-open wrapper. Never crashes the agent."""
        try:
            return await self.record_action(**kwargs)
        except Exception as e:
            self._pending_gap = True
            self._gap_detail = str(e)[:200]
            return None

    async def _emit_pending_gap(self) -> None:
        """Emit a GapRecord for a previously failed recording."""
        try:
            seq = self.writer.sequence
            await self.writer.write_record(GapPayload(
                first_lost_sequence=seq + 1,
                last_lost_sequence=seq + 1,
                count=1,
                reason=5,  # INTERCEPTOR_FAILURE
                detail=self._gap_detail,
            ))
            self._pending_gap = False
            self._gap_detail = ""
        except Exception:
            pass

    @classmethod
    async def from_config(cls, config_path: str, agent_name: str = "") -> 'AsyncAHPRecorder':
        """Create from config file and start."""
        from ahp.config import load_config
        config = load_config(config_path, agent_name)
        recorder = cls(agent_name=agent_name, config=config)
        await recorder.start()
        return recorder
