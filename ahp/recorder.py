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

import json
import logging
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Callable, List, Optional

from ahp._base_recorder import RecorderBase
from ahp.config import AHPConfig, load_config
from ahp.core.chain import ChainWriter
from ahp.core.filters import Filter
from ahp.core.records import (
    ActionPayload,
    Authorization,
    Record,
    WitnessPayload,
)
from ahp.core.recovery import recover_chain
from ahp.core.signing import sign
from ahp.core.types import (
    ZERO_UUID,
    ActionType,
    AuthorizationType,
    GapReason,
    Protocol,
    ResultStatus,
)
from ahp.core.witness_client import send_checkpoint as _send_checkpoint

logger = logging.getLogger("ahp.recorder")

DEFAULT_MAX_SEGMENT_BYTES = 64 * 1024 * 1024  # 64MB


class AHPRecorder(RecorderBase):
    """Main SDK entry point -- wires all AHP components together.

    Fail-open by design: recording failures NEVER propagate to the host agent.
    All public methods that write records catch exceptions internally when used
    via :meth:`safe_record`.

    Lock hierarchy (acquire in this order to prevent deadlocks):
      1. self._recorder_lock (RLock) — protects counters and checkpoint logic
      2. self._chain._lock (Lock) — protects chain file I/O
    Never acquire _recorder_lock while holding _chain._lock.
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
        on_record_written: Optional[Callable[[Record], None]] = None,
        on_error: Optional[Callable[[Exception, str], None]] = None,
    ) -> None:
        # ---- shared initialization (config, filters, evidence, signing) ----
        self._init_shared_components(
            agent_name=agent_name,
            level=level,
            config=config,
            evidence_path=evidence_path,
            filter_presets=filter_presets,
            custom_filters=custom_filters,
            agent_framework=agent_framework,
            interceptors=interceptors,
            checkpoint_interval=checkpoint_interval,
            witness_interval=witness_interval,
            witness_endpoints=witness_endpoints,
            on_record_written=on_record_written,
            on_error=on_error,
        )

        # ---- chain writer (with recovery + rotation) -----------------------
        if chain_path is None:
            chain_path = str(Path(tempfile.gettempdir()) / ("ahp_" + agent_name + ".ahp"))
        self._chain_path = chain_path

        # Recovery: if chain file already exists, scan and truncate corrupt tail
        self._recovery_result = None
        if Path(chain_path).exists():
            try:
                self._recovery_result = recover_chain(chain_path)
                if self._recovery_result.records_truncated > 0:
                    self._log_warning(
                        "Recovered chain %s: %d verified, %d truncated",
                        chain_path,
                        self._recovery_result.records_verified,
                        self._recovery_result.records_truncated,
                    )
            except Exception as exc:
                self._log_warning("Chain recovery failed for %s", chain_path, exc_info=True)
                self._fire_error_callback(exc, "chain_recovery")

        # Continue chain from recovery state if available
        if self._recovery_result is not None and self._recovery_result.records_verified > 0:
            self._chain = ChainWriter(
                chain_path,
                prev_hash=self._recovery_result.last_prev_hash,
                start_sequence=self._recovery_result.last_valid_seq,
            )
        else:
            self._chain = ChainWriter(chain_path)

        # Rotation support: track segment size limit
        self._max_segment_bytes = DEFAULT_MAX_SEGMENT_BYTES  # 64MB

        # Update evidence path if not explicitly set
        if self._evidence_enabled and self._evidence is not None:
            if evidence_path is None:
                epath = str(Path(chain_path).parent / "evidence")
                from ahp.core.evidence import EvidenceStore

                self._evidence = EvidenceStore(epath)

        # ---- concurrency lock for counters -----------------------------------
        self._recorder_lock = threading.RLock()

        # ---- emit genesis records ------------------------------------------
        self._emit_boot_record()
        if self._level >= 2 and self._keypair is not None:
            self._emit_key_genesis_record()

        # ---- emit recovery + gap records if recovery found corrupt data ----
        if self._recovery_result is not None and self._recovery_result.records_truncated > 0:
            self._emit_recovery_records(self._recovery_result)

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
        # Phase 1: Outside lock — pure computation + idempotent I/O
        param_hash, result_hash, filtered_params, filtered_result, redacted = self._filter_action_payloads(
            parameters, result
        )
        evidence_uri = self._store_evidence(filtered_params, filtered_result, param_hash)

        # Apply PII filters to string fields that go directly into the chain
        if target_entity and self._filters.filters:
            filtered_te, te_redacted = self._filters.apply(target_entity.encode("utf-8"), scope="parameters")
            target_entity = filtered_te.decode("utf-8")
            if te_redacted:
                redacted = True

        # Phase 2: Inside lock — state mutations only
        with self._recorder_lock:
            self._flush_pending_gap()

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

            record = self._chain.write_record(payload)
            self._track_record(record)

            if self._records_since_checkpoint >= self._checkpoint_interval:
                self.emit_checkpoint()

            if self._level >= 3 and self._witness_endpoints and self._records_since_witness >= self._witness_interval:
                self.send_witness_checkpoint()

            self._check_rotation()

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
        payload = self._build_checkpoint_payload(
            record_count=self._chain.record_count + 1,
            gap_count=self._chain.gap_count,
            chain_hash=self._chain.prev_hash,
        )

        record = self._chain.write_record(payload)

        # Reset counters (shared logic from base)
        self._reset_checkpoint_counters()

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
        public_key_hex = ""
        if self._level >= 2 and self._keypair is not None:
            # Sign canonical JSON of checkpoint fields (must match witness verification)
            sign_data = json.dumps(
                {
                    "agent_id": agent_id_hex,
                    "chain_hash": chain_hash_hex,
                    "sequence": sequence,
                    "timestamp_ms": timestamp_ms,
                },
                sort_keys=True,
            ).encode()
            sig_hex = sign(sign_data, self._keypair.private_key_bytes).hex()
            key_id_hex = self._keypair.key_id.hex()
            public_key_hex = self._keypair.public_key_bytes.hex()

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
                    public_key=public_key_hex,
                )
                if receipt is not None:
                    witness_payload = WitnessPayload(
                        witness_id=receipt.get("witness_id", endpoint),
                        checkpoint_seq=sequence,
                        checkpoint_hash=self._chain.prev_hash,
                        witness_timestamp=receipt.get("timestamp_ms", timestamp_ms),
                        receipt_signature=bytes.fromhex(receipt.get("signature", "00" * 64)),
                        witness_public_key=bytes.fromhex(receipt.get("public_key", "00" * 32)),
                    )
                    self._chain.write_record(witness_payload)
            except Exception as exc:
                self._log_warning("Witness checkpoint to %s failed", endpoint, exc_info=True)
                self._fire_error_callback(exc, "witness_checkpoint")

        self._reset_witness_counter()

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
            self._log_warning("AHP safe_record failed (will emit GapRecord): %s", exc)
            self._fire_error_callback(exc, "safe_record")
            return None

    # ------------------------------------------------------------------
    # Resource management
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Release resources held by the recorder (chain writer, file locks)."""
        self._chain.close()

    def __enter__(self) -> "AHPRecorder":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

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

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _emit_boot_record(self) -> None:
        """Write the BootRecord as the very first record in the chain."""
        payload = self._build_boot_payload()
        record = self._chain.write_record(payload)
        self._track_record(record)

    def _emit_key_genesis_record(self) -> None:
        """Write a KeyGenesisRecord (level >= 2)."""
        payload = self._build_key_genesis_payload()
        if payload is None:
            return
        record = self._chain.write_record(payload)
        self._track_record(record)

    def _flush_pending_gap(self) -> None:
        """If a previous safe_record failed, emit a GapRecord now.

        Called from record_action() which already holds _recorder_lock.
        """
        if not self._pending_gap:
            return

        first_lost = self._gap_first_lost_seq
        last_lost = self._chain.sequence

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

    def _emit_recovery_records(self, recovery_result) -> None:
        """Emit RecoveryRecord + GapRecord after crash recovery (per spec Section 3.6)."""
        from ahp.core.types import RecoveryMethod

        recovery_record = self._chain.write_recovery(
            records_verified=recovery_result.records_verified,
            records_truncated=recovery_result.records_truncated,
            last_valid_seq=recovery_result.last_valid_seq,
            method=RecoveryMethod.CHAIN_SCAN,
            detail="Automatic crash recovery on startup",
        )
        self._track_record(recovery_record)

        if recovery_result.records_truncated > 0:
            first_lost = recovery_result.last_valid_seq + 1
            last_lost = first_lost + recovery_result.records_truncated - 1
            gap_record = self._chain.write_gap(
                first_lost=first_lost,
                last_lost=last_lost,
                reason=GapReason.CRASH,
                detail="Records lost during crash recovery",
            )
            self._track_record(gap_record)

    def _check_rotation(self) -> None:
        """Rotate the chain file if it exceeds 64MB."""
        chain_size = self._chain.bytes_written

        if chain_size < self._max_segment_bytes:
            return

        logger.info(
            "Chain file %s reached %d bytes, rotating",
            self._chain_path,
            chain_size,
        )

        prev_hash = self._chain.prev_hash
        prev_sequence = self._chain.sequence

        self._chain.close()

        timestamp = int(time.time())
        segment_path = self._chain_path + f".{timestamp}.segment"
        try:
            os.rename(self._chain_path, segment_path)
        except OSError:
            self._log_warning("Failed to rename chain for rotation", exc_info=True)

        self._chain = ChainWriter(
            self._chain_path,
            prev_hash=prev_hash,
            start_sequence=prev_sequence,
        )

        self._emit_boot_record()
        if self._level >= 2 and self._keypair is not None:
            self._emit_key_genesis_record()
