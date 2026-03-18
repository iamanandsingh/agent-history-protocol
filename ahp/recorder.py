"""AHPRecorder -- the main SDK entry point.

Wires together: chain writer + evidence store + PII filters + signing +
witness client + context propagation into one automated flow.

Usage:
    from ahp.recorder import AHPRecorder

    recorder = AHPRecorder(agent_name="my-agent")
    # or with config file:
    recorder = AHPRecorder.from_config("ahp.yaml", agent_name="my-agent")

    # Record actions (fail-open -- never crashes the agent)
    recorder.record_action(
        tool_name="search_docs",
        parameters=b'{"query": "return policy"}',
        result=b'{"matches": [...]}',
        protocol=Protocol.MCP,
        action_type=ActionType.TOOL_CALL,
    )
"""
from __future__ import annotations

import hashlib
import logging
import platform
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from ahp.config import AHPConfig, FilterConfig, WitnessConfig, load_config
from ahp.core.chain import ChainWriter, ChainReader
from ahp.core.evidence import EvidenceStore
from ahp.core.filters import Filter, FilterPipeline
from ahp.core.records import (
    Record,
    ActionPayload,
    BootPayload,
    CheckpointPayload,
    GapPayload,
    KeyPayload,
    WitnessPayload,
    Authorization,
)
from ahp.core.signing import (
    KeyPair,
    generate_keypair,
    sign,
    verify_signature,
    compute_merkle_root,
)
from ahp.core.types import (
    RecordType,
    ResultStatus,
    Protocol,
    ActionType,
    AuthorizationType,
    GapReason,
    ChainLevel,
    FsyncMode,
    ZERO_HASH_16,
    ZERO_HASH_32,
    ZERO_UUID,
)
from ahp.core.uuid7 import uuid7
from ahp.core.witness_client import send_checkpoint as _send_checkpoint

logger = logging.getLogger("ahp.recorder")

# SDK identity constants
_SDK_NAME = "ahp-python"
_SDK_VERSION = "0.1.0"

# Map string fsync modes from config to enum values
_FSYNC_MAP = {
    "every": FsyncMode.EVERY,
    "batch": FsyncMode.BATCH,
    "none": FsyncMode.NONE,
}


class AHPRecorder:
    """Main SDK entry point -- wires all AHP components together.

    Fail-open by design: recording failures NEVER propagate to the host agent.
    All public methods that write records catch exceptions internally when used
    via :meth:`safe_record`.
    """

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def __init__(
        self,
        agent_name: str,
        chain_path: Optional[str] = None,
        level: int = 1,
        config: Optional[AHPConfig] = None,
        evidence_path: Optional[str] = None,
        checkpoint_interval: int = 1000,
        witness_interval: int = 1000,
        witness_endpoints: Optional[List[str]] = None,
        filter_presets: Optional[List[str]] = None,
        custom_filters: Optional[List[Filter]] = None,
        agent_framework: str = "",
        interceptors: Optional[List[str]] = None,
    ) -> None:
        # ---- resolve config ------------------------------------------------
        if config is not None:
            self._cfg = config
        else:
            self._cfg = AHPConfig(
                level=level,
                agent_name=agent_name,
                agent_framework=agent_framework,
                checkpoint_interval=checkpoint_interval,
                witness=WitnessConfig(
                    enabled=(level == 3),
                    interval=witness_interval,
                    endpoints=witness_endpoints or [],
                ),
                filter_presets=filter_presets or [],
            )

        # Override agent_name from explicit arg (takes precedence over config)
        self._agent_name = agent_name
        self._level = self._cfg.level
        self._checkpoint_interval = self._cfg.checkpoint_interval
        self._witness_interval = self._cfg.witness.interval
        self._witness_endpoints = list(self._cfg.witness.endpoints)
        self._agent_framework = self._cfg.agent_framework or agent_framework
        self._interceptors = interceptors or []

        # ---- chain writer ---------------------------------------------------
        if chain_path is None:
            chain_path = str(
                Path(tempfile.gettempdir()) / ("ahp_" + agent_name + ".ahp")
            )
        self._chain = ChainWriter(chain_path)

        # ---- evidence store -------------------------------------------------
        self._evidence_enabled = self._cfg.evidence_record
        self._evidence = None  # type: Optional[EvidenceStore]
        if self._evidence_enabled:
            epath = evidence_path or str(
                Path(chain_path).parent / "evidence"
            )
            self._evidence = EvidenceStore(epath)

        # ---- PII filter pipeline --------------------------------------------
        preset_list = list(self._cfg.filter_presets)
        if filter_presets:
            for p in filter_presets:
                if p not in preset_list:
                    preset_list.append(p)

        custom_filter_list = list(custom_filters or [])
        # Also include filters defined in config
        for fc in self._cfg.filters:
            custom_filter_list.append(
                Filter(
                    name=fc.name,
                    pattern=fc.pattern,
                    replacement=fc.replacement,
                    scope=list(fc.scope),
                )
            )
        self._filters = FilterPipeline(
            filters=custom_filter_list if custom_filter_list else None,
            presets=preset_list if preset_list else None,
        )

        # ---- signing (level >= 2) ------------------------------------------
        self._keypair = None  # type: Optional[KeyPair]
        if self._level >= 2:
            self._keypair = generate_keypair()

        # ---- internal counters ----------------------------------------------
        self._records_since_checkpoint = 0  # type: int
        self._record_hashes_since_checkpoint = []  # type: List[bytes]
        self._records_since_witness = 0  # type: int

        # ---- fail-open gap state -------------------------------------------
        self._pending_gap = False
        self._gap_reason = ""  # type: str
        self._gap_detail = ""  # type: str
        self._gap_first_lost_seq = 0  # type: int

        # ---- emit genesis records ------------------------------------------
        self._emit_boot_record()
        if self._level >= 2 and self._keypair is not None:
            self._emit_key_genesis_record()

    # ------------------------------------------------------------------
    # Class-method constructors
    # ------------------------------------------------------------------

    @classmethod
    def from_config(
        cls,
        config_path: str,
        agent_name: str,
        chain_path: Optional[str] = None,
        evidence_path: Optional[str] = None,
    ) -> "AHPRecorder":
        """Create an AHPRecorder from a YAML/JSON configuration file."""
        cfg = load_config(config_path, agent_name=agent_name)
        return cls(
            agent_name=agent_name,
            config=cfg,
            chain_path=chain_path,
            evidence_path=evidence_path,
        )

    # ------------------------------------------------------------------
    # Core recording methods
    # ------------------------------------------------------------------

    def record_action(
        self,
        tool_name: str,
        parameters: bytes = b"",
        result: bytes = b"",
        protocol: Protocol = Protocol.CUSTOM,
        action_type: ActionType = ActionType.TOOL_CALL,
        result_status: ResultStatus = ResultStatus.SUCCESS,
        response_time_ms: int = 0,
        target_entity: str = "",
        parent_action_id: bytes = ZERO_UUID,
        authorization: Optional[Authorization] = None,
        model_id: str = "",
        input_token_count: int = 0,
        output_token_count: int = 0,
    ) -> Record:
        """Record a single agent action.

        This is the primary recording method.  It filters PII, hashes
        content, optionally stores evidence, writes to the chain, and
        triggers checkpoints / witness submissions when their intervals
        are reached.

        Returns the :class:`Record` written to the chain.
        """
        # 0. If there is a pending gap from a previous failure, emit it first.
        self._flush_pending_gap()

        # 1. Apply PII filters
        param_hash, filtered_params, param_redacted = self._filters.hash_payload(
            parameters, scope="parameters"
        )
        result_hash, filtered_result, result_redacted = self._filters.hash_payload(
            result, scope="results"
        )
        redacted = param_redacted or result_redacted

        # 2. Store evidence if configured
        evidence_uri = ""
        if self._evidence is not None and (filtered_params or filtered_result):
            # Store both parameters and result as evidence
            if filtered_params:
                self._evidence.store(filtered_params)
            if filtered_result:
                self._evidence.store(filtered_result)
            evidence_uri = "evidence://" + param_hash.hex()

        # 3. Build payload
        payload = ActionPayload(
            parent_action_id=parent_action_id,
            tool_name=tool_name,
            parameters_hash=param_hash,
            result_hash=result_hash,
            result_status=result_status,
            response_time_ms=response_time_ms,
            protocol=protocol,
            action_type=action_type,
            target_entity=target_entity,
            evidence_uri=evidence_uri,
            redacted=redacted,
            model_id=model_id,
            input_token_count=input_token_count,
            output_token_count=output_token_count,
            authorization=authorization or Authorization(type=AuthorizationType.AUTH_NONE),
        )

        # 4. Write to chain (thread-safe via ChainWriter lock)
        record = self._chain.write_record(payload)

        # 5. Track checkpoint state
        self._track_record(record)

        # 6. Auto-checkpoint
        if self._records_since_checkpoint >= self._checkpoint_interval:
            self.emit_checkpoint()

        # 7. Auto-witness (level 3 only)
        if (
            self._level >= 3
            and self._witness_endpoints
            and self._records_since_witness >= self._witness_interval
        ):
            self.send_witness_checkpoint()

        return record

    def record_inference(
        self,
        tool_name: str,
        parameters: bytes = b"",
        result: bytes = b"",
        model_id: str = "",
        input_token_count: int = 0,
        output_token_count: int = 0,
        protocol: Protocol = Protocol.CUSTOM,
        result_status: ResultStatus = ResultStatus.SUCCESS,
        response_time_ms: int = 0,
        target_entity: str = "",
        parent_action_id: bytes = ZERO_UUID,
        authorization: Optional[Authorization] = None,
    ) -> Record:
        """Record an inference (LLM) call.

        Convenience wrapper around :meth:`record_action` that sets
        ``action_type=INFERENCE`` and populates model / token fields.
        """
        return self.record_action(
            tool_name=tool_name,
            parameters=parameters,
            result=result,
            protocol=protocol,
            action_type=ActionType.INFERENCE,
            result_status=result_status,
            response_time_ms=response_time_ms,
            target_entity=target_entity,
            parent_action_id=parent_action_id,
            authorization=authorization,
            model_id=model_id,
            input_token_count=input_token_count,
            output_token_count=output_token_count,
        )

    # ------------------------------------------------------------------
    # Checkpointing
    # ------------------------------------------------------------------

    def emit_checkpoint(self) -> Record:
        """Emit a checkpoint record.

        Computes the Merkle root of records since the last checkpoint,
        signs it when ``level >= 2``, and writes a
        :class:`CheckpointPayload` to the chain.
        """
        merkle_root = compute_merkle_root(self._record_hashes_since_checkpoint)

        signature = b"\x00" * 64
        signing_key_id = ZERO_HASH_32
        if self._level >= 2 and self._keypair is not None:
            signature = sign(merkle_root, self._keypair.private_key_bytes)
            signing_key_id = self._keypair.key_id

        evidence_status = self._get_evidence_status()

        payload = CheckpointPayload(
            record_count=self._chain.record_count + 1,  # including this checkpoint
            gap_count=self._chain.gap_count,
            chain_hash=self._chain.prev_hash,
            merkle_root=merkle_root,
            signature=signature,
            signing_key_id=signing_key_id,
            evidence_available=evidence_status.get("available", 0),
            evidence_exported=evidence_status.get("exported", 0),
            evidence_expired=evidence_status.get("expired", 0),
            evidence_missing=evidence_status.get("missing", 0),
        )

        record = self._chain.write_record(payload)

        # Reset counters
        self._records_since_checkpoint = 0
        self._record_hashes_since_checkpoint = []

        return record

    # ------------------------------------------------------------------
    # Witness
    # ------------------------------------------------------------------

    def send_witness_checkpoint(self) -> None:
        """Send the current chain state to all configured witness endpoints.

        On receipt, a :class:`WitnessPayload` is written to the chain.
        On failure, the error is logged but does NOT block the agent
        (per spec Section 8.5).
        """
        agent_id_hex = self._chain.agent_id.hex()
        chain_hash_hex = self._chain.prev_hash.hex()
        sequence = self._chain.sequence
        timestamp_ms = int(time.time() * 1000)

        sig_hex = ""
        key_id_hex = ""
        if self._level >= 2 and self._keypair is not None:
            sig_hex = sign(
                self._chain.prev_hash, self._keypair.private_key_bytes
            ).hex()
            key_id_hex = self._keypair.key_id.hex()

        for endpoint in self._witness_endpoints:
            try:
                receipt = _send_checkpoint(
                    endpoint=endpoint,
                    agent_id=agent_id_hex,
                    chain_hash=chain_hash_hex,
                    sequence=sequence,
                    timestamp_ms=timestamp_ms,
                    signature=sig_hex,
                    signing_key_id=key_id_hex,
                )
                if receipt is not None:
                    witness_payload = WitnessPayload(
                        witness_id=receipt.get("witness_id", endpoint),
                        checkpoint_seq=sequence,
                        checkpoint_hash=self._chain.prev_hash,
                        witness_timestamp=receipt.get("timestamp_ms", timestamp_ms),
                        receipt_signature=bytes.fromhex(
                            receipt.get("signature", "00" * 64)
                        ),
                        witness_public_key=bytes.fromhex(
                            receipt.get("public_key", "00" * 32)
                        ),
                    )
                    self._chain.write_record(witness_payload)
            except Exception:
                # Per spec Section 8.5: log, do not block the agent.
                logger.warning(
                    "Witness checkpoint to %s failed", endpoint, exc_info=True
                )

        self._records_since_witness = 0

    # ------------------------------------------------------------------
    # Fail-open wrapper
    # ------------------------------------------------------------------

    def safe_record(self, **kwargs) -> Optional[Record]:  # type: ignore[return]
        """Fail-open wrapper around :meth:`record_action`.

        If recording raises an exception the error is captured and a
        :class:`GapRecord` will be emitted on the next successful write.
        The host agent is never disrupted.
        """
        try:
            return self.record_action(**kwargs)
        except Exception as exc:
            # Remember the gap so the next successful write can document it.
            if not self._pending_gap:
                self._gap_first_lost_seq = self._chain.sequence + 1
            self._pending_gap = True
            self._gap_reason = "INTERCEPTOR_FAILURE"
            self._gap_detail = str(exc)
            logger.warning("AHP safe_record failed (will emit GapRecord): %s", exc)
            return None

    # ------------------------------------------------------------------
    # Read-only accessors
    # ------------------------------------------------------------------

    @property
    def chain_path(self) -> str:
        """Path to the chain file."""
        return str(self._chain.path)

    @property
    def chain(self) -> ChainWriter:
        """Underlying :class:`ChainWriter` (read-only access)."""
        return self._chain

    @property
    def level(self) -> int:
        return self._level

    @property
    def keypair(self) -> Optional[KeyPair]:
        return self._keypair

    @property
    def evidence_store(self) -> Optional[EvidenceStore]:
        return self._evidence

    @property
    def filter_pipeline(self) -> FilterPipeline:
        return self._filters

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _emit_boot_record(self) -> None:
        """Write the BootRecord as the very first record in the chain."""
        runtime_info = "python %s / %s" % (
            platform.python_version(),
            platform.system(),
        )

        fsync_mode = _FSYNC_MAP.get(self._cfg.fsync_mode, FsyncMode.BATCH)

        payload = BootPayload(
            sdk_name=_SDK_NAME,
            sdk_version=_SDK_VERSION,
            interceptors=self._interceptors,
            agent_framework=self._agent_framework,
            agent_name=self._agent_name,
            runtime=runtime_info,
            chain_level=ChainLevel(self._level),
            fsync_mode=fsync_mode,
            clock_source="system",
            inference_recording=self._cfg.inference_record,
            inference_evidence=self._cfg.inference_evidence,
            evidence_recording=self._cfg.evidence_record,
            filter_config_hash=self._filters.config_hash(),
            matched_agent_rule=self._cfg.matched_agent_rule,
            config_source=self._cfg.config_source,
            authorization_recording=self._cfg.authorization_record,
        )

        record = self._chain.write_record(payload)
        self._track_record(record)

    def _emit_key_genesis_record(self) -> None:
        """Write a KeyGenesisRecord (level >= 2)."""
        if self._keypair is None:
            return

        payload = KeyPayload(
            public_key=self._keypair.public_key_bytes,
            key_id=self._keypair.key_id,
            expires_at=0,  # no expiry for session keys
            supersedes_key_id=ZERO_HASH_32,
        )

        record = self._chain.write_record(payload)
        self._track_record(record)

    def _track_record(self, record: Record) -> None:
        """Update internal counters after a record is written."""
        self._records_since_checkpoint += 1
        self._records_since_witness += 1

        # Keep the SHA-256 of the canonical bytes for Merkle tree
        if record._stored_bytes is not None:
            self._record_hashes_since_checkpoint.append(
                hashlib.sha256(record._stored_bytes).digest()
            )

    def _flush_pending_gap(self) -> None:
        """If a previous safe_record failed, emit a GapRecord now."""
        if not self._pending_gap:
            return

        first_lost = self._gap_first_lost_seq
        last_lost = self._chain.sequence  # current tip; gap covers up to here

        # If first_lost > last_lost it means no sequence numbers were actually
        # skipped (the failure happened before any sequence was consumed).
        # Emit a single-record gap documenting the failure anyway.
        if first_lost > last_lost:
            last_lost = first_lost

        reason = GapReason.INTERCEPTOR_FAILURE
        gap_record = self._chain.write_gap(
            first_lost=first_lost,
            last_lost=last_lost,
            reason=reason,
            detail=self._gap_detail,
        )
        self._track_record(gap_record)

        self._pending_gap = False
        self._gap_reason = ""
        self._gap_detail = ""
        self._gap_first_lost_seq = 0

    def _get_evidence_status(self) -> Dict[str, int]:
        """Return evidence status counts for checkpoint payload."""
        if self._evidence is not None:
            counts = self._evidence.count()
            return {
                "available": counts.get("available", 0),
                "exported": 0,
                "expired": 0,
                "missing": counts.get("missing", 0),
            }
        return {"available": 0, "exported": 0, "expired": 0, "missing": 0}
