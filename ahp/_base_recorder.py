"""Shared recorder logic between sync and async recorders.

Consolidates: PII filter setup, hash_payload logic, evidence store setup,
boot payload construction, checkpoint payload construction (merkle root,
signing), key genesis payload construction, and config resolution.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import logging
import platform
from typing import Any, Callable, Dict, List, Optional, Tuple

from ahp.config import AHPConfig, WitnessConfig
from ahp.core.evidence import EvidenceStore
from ahp.core.filters import Filter, FilterPipeline
from ahp.core.records import (
    BootPayload,
    CheckpointPayload,
    KeyPayload,
    Record,
)
from ahp.core.signing import (
    HAS_CRYPTO,
    KeyPair,
    compute_merkle_root,
    generate_keypair,
    sign,
)
from ahp.core.types import (
    ZERO_HASH_32,
    ChainLevel,
    FsyncMode,
)

logger = logging.getLogger("ahp.recorder")

# SDK identity constants
SDK_NAME = "ahp-python"
try:
    SDK_VERSION = importlib.metadata.version("open-ahp")
except importlib.metadata.PackageNotFoundError:
    SDK_VERSION = "0.1.0"

# Map string fsync modes from config to enum values
FSYNC_MAP = {
    "every": FsyncMode.EVERY,
    "batch": FsyncMode.BATCH,
    "none": FsyncMode.NONE,
}


class RecorderBase:
    """Shared logic for sync and async recorders.

    Provides: config resolution, PII filtering, evidence storage,
    hash computation, boot/key/checkpoint payload construction,
    structured logging, and callback hooks.

    Subclasses must set:
      - self._agent_name
      - self._level
      - self._cfg
    before calling _init_shared_components().
    """

    # ----------------------------------------------------------------
    # Shared initialization
    # ----------------------------------------------------------------

    def _init_shared_components(
        self,
        agent_name: str,
        level: int,
        config: Optional[AHPConfig],
        evidence_path: Optional[str],
        filter_presets: Optional[List[str]],
        custom_filters: Optional[List[Filter]],
        agent_framework: str = "",
        interceptors: Optional[List[str]] = None,
        checkpoint_interval: int = 1000,
        witness_interval: int = 1000,
        witness_endpoints: Optional[List[str]] = None,
        on_record_written: Optional[Callable[[Record], None]] = None,
        on_error: Optional[Callable[[Exception, str], None]] = None,
    ) -> None:
        """Initialize all shared components. Call from subclass __init__."""
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

        self._agent_name = agent_name
        self._level = self._cfg.level
        self._checkpoint_interval = self._cfg.checkpoint_interval
        self._witness_interval = self._cfg.witness.interval
        self._witness_endpoints = list(self._cfg.witness.endpoints)
        self._agent_framework = self._cfg.agent_framework or agent_framework
        self._interceptors = interceptors or []

        # ---- callback hooks ------------------------------------------------
        self._on_record_written = on_record_written
        self._on_error = on_error

        # ---- early crypto validation (level >= 2) --------------------------
        if self._level >= 2:
            if not HAS_CRYPTO:
                raise RuntimeError("Level 2+ requires 'cryptography' package. Install with: pip install ahp[signing]")

        # ---- evidence store ------------------------------------------------
        self._evidence_enabled = self._cfg.evidence_record
        self._evidence: Optional[EvidenceStore] = None
        if self._evidence_enabled:
            epath = evidence_path or "evidence"
            self._evidence = EvidenceStore(epath)

        # ---- PII filter pipeline -------------------------------------------
        preset_list = list(self._cfg.filter_presets)
        if filter_presets:
            for p in filter_presets:
                if p not in preset_list:
                    preset_list.append(p)

        custom_filter_list = list(custom_filters or [])
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
        self._keypair: Optional[KeyPair] = None
        if self._level >= 2:
            self._keypair = generate_keypair()

        # ---- internal counters ---------------------------------------------
        self._records_since_checkpoint = 0
        self._record_hashes_since_checkpoint: List[bytes] = []
        self._records_since_witness = 0

        # ---- pricing (apply user overrides from config) ----------------------
        if self._cfg.pricing:
            from ahp.core.pricing import set_pricing

            user_pricing = {e.model: (e.input, e.output) for e in self._cfg.pricing}
            set_pricing(user_pricing, merge=True)

        # ---- provider patterns (apply user overrides from config) -----------
        if self._cfg.providers:
            from ahp.interceptors.http_helper import add_provider_patterns

            add_provider_patterns([(p.pattern, p.name, p.provider) for p in self._cfg.providers])

        # ---- fail-open gap state -------------------------------------------
        self._pending_gap = False
        self._gap_reason = ""
        self._gap_detail = ""
        self._gap_first_lost_seq = 0

    # ----------------------------------------------------------------
    # PII filtering + hashing
    # ----------------------------------------------------------------

    def _filter_and_hash(self, payload: bytes, scope: str) -> Tuple[bytes, bytes, bool]:
        """Apply PII filters and compute hash.

        Returns (hash_16, filtered_payload, was_redacted).
        """
        return self._filters.hash_payload(payload, scope=scope)

    def _filter_action_payloads(self, parameters: bytes, result: bytes) -> Tuple[bytes, bytes, bytes, bytes, bool]:
        """Filter both parameters and result.

        Returns (param_hash, result_hash, filtered_params, filtered_result, redacted).
        """
        param_hash, filtered_params, param_redacted = self._filter_and_hash(parameters, scope="parameters")
        result_hash, filtered_result, result_redacted = self._filter_and_hash(result, scope="results")
        redacted = param_redacted or result_redacted
        return param_hash, result_hash, filtered_params, filtered_result, redacted

    # ----------------------------------------------------------------
    # Evidence storage
    # ----------------------------------------------------------------

    def _store_evidence(self, filtered_params: bytes, filtered_result: bytes, param_hash: bytes) -> str:
        """Store evidence payloads if evidence is enabled.

        Returns the evidence URI or empty string.
        """
        evidence_uri = ""
        if self._evidence is not None and (filtered_params or filtered_result):
            if filtered_params:
                self._evidence.store(filtered_params)
            if filtered_result:
                self._evidence.store(filtered_result)
            evidence_uri = "evidence://" + param_hash.hex()
        return evidence_uri

    # ----------------------------------------------------------------
    # Payload construction
    # ----------------------------------------------------------------

    def _build_boot_payload(self) -> BootPayload:
        """Construct a BootPayload from current config."""
        runtime_info = "python %s / %s" % (
            platform.python_version(),
            platform.system(),
        )
        fsync_mode = FSYNC_MAP.get(self._cfg.fsync_mode, FsyncMode.BATCH)

        return BootPayload(
            sdk_name=SDK_NAME,
            sdk_version=SDK_VERSION,
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

    def _build_key_genesis_payload(self) -> Optional[KeyPayload]:
        """Construct a KeyPayload for level >= 2. Returns None if no keypair."""
        if self._keypair is None:
            return None
        return KeyPayload(
            public_key=self._keypair.public_key_bytes,
            key_id=self._keypair.key_id,
            expires_at=0,
            supersedes_key_id=ZERO_HASH_32,
        )

    def _build_checkpoint_payload(self, record_count: int, gap_count: int, chain_hash: bytes) -> CheckpointPayload:
        """Construct a CheckpointPayload with merkle root and signature."""
        merkle_root = compute_merkle_root(self._record_hashes_since_checkpoint)

        signature = b"\x00" * 64
        signing_key_id = ZERO_HASH_32
        if self._level >= 2 and self._keypair is not None:
            signature = sign(merkle_root, self._keypair.private_key_bytes)
            signing_key_id = self._keypair.key_id

        evidence_status = self._get_evidence_status()

        return CheckpointPayload(
            record_count=record_count,
            gap_count=gap_count,
            chain_hash=chain_hash,
            merkle_root=merkle_root,
            signature=signature,
            signing_key_id=signing_key_id,
            evidence_available=evidence_status.get("available", 0),
            evidence_exported=evidence_status.get("exported", 0),
            evidence_expired=evidence_status.get("expired", 0),
            evidence_missing=evidence_status.get("missing", 0),
        )

    # ----------------------------------------------------------------
    # Record tracking
    # ----------------------------------------------------------------

    def _track_record(self, record: Record) -> None:
        """Update internal counters after a record is written."""
        self._records_since_checkpoint += 1
        self._records_since_witness += 1

        if record._stored_bytes is not None:
            self._record_hashes_since_checkpoint.append(hashlib.sha256(record._stored_bytes).digest())

        # Fire callback hook
        if self._on_record_written is not None:
            try:
                self._on_record_written(record)
            except Exception:
                pass  # Never let callback failures propagate

    def _reset_checkpoint_counters(self) -> None:
        """Reset counters after a checkpoint is emitted."""
        self._records_since_checkpoint = 0
        self._record_hashes_since_checkpoint = []

    def _reset_witness_counter(self) -> None:
        """Reset the witness counter."""
        self._records_since_witness = 0

    # ----------------------------------------------------------------
    # Evidence helpers
    # ----------------------------------------------------------------

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

    # ----------------------------------------------------------------
    # Structured logging helpers
    # ----------------------------------------------------------------

    def _log_warning(self, msg: str, *args: Any, **kwargs: Any) -> None:
        """Log a warning with structured context fields."""
        _chain = getattr(self, "_chain", None)
        extra = {
            "agent_id": _chain and getattr(_chain, "agent_id", b"").hex() or "",
            "session_id": _chain and getattr(_chain, "session_id", b"").hex() or "",
            "record_count": self._records_since_checkpoint,
        }
        logger.warning(
            msg + " [agent_id=%s session_id=%s records=%d]",
            *args,
            extra["agent_id"],
            extra["session_id"],
            extra["record_count"],
            **kwargs,
        )

    def _fire_error_callback(self, exc: Exception, context: str) -> None:
        """Fire the on_error callback if set."""
        if self._on_error is not None:
            try:
                self._on_error(exc, context)
            except Exception:
                pass  # Never let callback failures propagate

    # ----------------------------------------------------------------
    # Read-only accessors (common)
    # ----------------------------------------------------------------

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
