"""Shared recorder logic between sync and async recorders."""
from __future__ import annotations
import hashlib
import platform
from typing import Optional, List, Any
from ahp.core.types import (
    AuthorizationType, ChainLevel, ZERO_HASH_16, ZERO_HASH_32,
)
from ahp.core.records import (
    ActionPayload, BootPayload, KeyPayload, Authorization,
)
from ahp.core.evidence import EvidenceStore
from ahp.core.filters import FilterPipeline
from ahp.core.signing import generate_keypair, sign, compute_merkle_root, HAS_CRYPTO
from ahp.config import AHPConfig, WitnessConfig

class RecorderMixin:
    """Shared logic for sync and async recorders.

    Provides: PII filtering, evidence storage, hash computation,
    boot payload creation, checkpoint payload creation.
    """

    def _init_components(self, config: AHPConfig, evidence_path: Optional[str],
                         filter_presets: Optional[List[str]]):
        self.evidence_store = None
        if config.evidence_record:
            self.evidence_store = EvidenceStore(evidence_path or "evidence")

        presets = filter_presets or config.filter_presets
        self.filter_pipeline = FilterPipeline(presets=presets) if presets else None

        self.keypair = None
        if config.level >= 2:
            self.keypair = generate_keypair()

    def _filter_and_hash(self, parameters: bytes, result: bytes):
        """Apply PII filters and compute hashes. Returns (params_hash, result_hash, filtered_params, filtered_result, redacted)."""
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
        return params_hash, result_hash, filtered_params, filtered_result, redacted

    def _store_evidence(self, filtered_params: bytes, filtered_result: bytes):
        if self.evidence_store:
            if filtered_params:
                self.evidence_store.store(filtered_params)
            if filtered_result:
                self.evidence_store.store(filtered_result)

    def _create_boot_payload(self, agent_name: str, config: AHPConfig) -> BootPayload:
        return BootPayload(
            sdk_name="ahp-python",
            sdk_version="0.1.0",
            agent_name=agent_name,
            runtime=f"python {platform.python_version()}",
            chain_level=ChainLevel(config.level),
            inference_recording=config.inference_record,
            inference_evidence=config.inference_evidence,
            evidence_recording=config.evidence_record,
            authorization_recording=config.authorization_record,
            filter_config_hash=self.filter_pipeline.config_hash() if self.filter_pipeline else ZERO_HASH_32,
        )

    def _create_key_payload(self) -> Optional[KeyPayload]:
        if self.keypair:
            return KeyPayload(
                public_key=self.keypair.public_key_bytes,
                key_id=self.keypair.key_id,
            )
        return None

    def _compute_checkpoint_signing(self, record_hashes: List[bytes]):
        """Compute merkle root and signature for checkpoint."""
        merkle_root = ZERO_HASH_32
        sig = b'\x00' * 64
        key_id = ZERO_HASH_32
        if record_hashes:
            merkle_root = compute_merkle_root(record_hashes)
        if self.keypair and HAS_CRYPTO:
            sig = sign(merkle_root, self.keypair.private_key_bytes)
            key_id = self.keypair.key_id
        return merkle_root, sig, key_id
