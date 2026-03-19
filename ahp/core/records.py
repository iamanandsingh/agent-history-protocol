"""AHP record data model — all 7 record types + authorization."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Union

from ahp.core.types import (
    SCHEMA_VERSION,
    ZERO_HASH_16,
    ZERO_HASH_32,
    ZERO_UUID,
    ActionType,
    AuthorizationDecision,
    AuthorizationType,
    AuthorizerType,
    ChainLevel,
    FsyncMode,
    GapReason,
    Protocol,
    RecordType,
    RecoveryMethod,
    ResultStatus,
)

# --- Authorization ---


@dataclass
class AuthorizationEntry:
    authorizer_type: AuthorizerType
    authorizer_id: str
    authorizer_agent_id: bytes = ZERO_UUID  # 16 bytes, optional
    authorizer_seq: int = 0  # 0 = not set
    decision: AuthorizationDecision = AuthorizationDecision.APPROVED
    condition: str = ""
    timestamp_ms: int = 0


@dataclass
class Authorization:
    type: AuthorizationType = AuthorizationType.AUTH_NONE
    entries: list[AuthorizationEntry] = field(default_factory=list)


# --- Payloads ---


@dataclass
class ActionPayload:
    parent_action_id: bytes = ZERO_UUID
    tool_name: str = ""
    parameters_hash: bytes = ZERO_HASH_16
    result_hash: bytes = ZERO_HASH_16
    result_status: ResultStatus = ResultStatus.SUCCESS
    response_time_ms: int = 0
    protocol: Protocol = Protocol.CUSTOM
    action_type: ActionType = ActionType.TOOL_CALL
    target_entity: str = ""
    evidence_uri: str = ""
    redacted: bool = False
    model_id: str = ""
    input_token_count: int = 0
    output_token_count: int = 0
    authorization: Authorization = field(default_factory=Authorization)


@dataclass
class GapPayload:
    first_lost_sequence: int = 0
    last_lost_sequence: int = 0
    count: int = 0
    reason: GapReason = GapReason.CRASH
    detail: str = ""


@dataclass
class CheckpointPayload:
    record_count: int = 0
    gap_count: int = 0
    chain_hash: bytes = ZERO_HASH_32
    merkle_root: bytes = ZERO_HASH_32
    signature: bytes = b"\x00" * 64
    signing_key_id: bytes = ZERO_HASH_32
    evidence_available: int = 0
    evidence_exported: int = 0
    evidence_expired: int = 0
    evidence_missing: int = 0


@dataclass
class BootPayload:
    sdk_name: str = "ahp-python"
    sdk_version: str = "0.1.0a1"
    interceptors: list[str] = field(default_factory=list)
    agent_framework: str = ""
    agent_name: str = ""
    runtime: str = ""
    chain_level: ChainLevel = ChainLevel.LEVEL_1
    fsync_mode: FsyncMode = FsyncMode.BATCH
    clock_source: str = "system"
    inference_recording: bool = True
    inference_evidence: bool = False
    evidence_recording: bool = False
    filter_config_hash: bytes = ZERO_HASH_32
    matched_agent_rule: str = ""
    config_source: str = ""
    authorization_recording: bool = False


@dataclass
class RecoveryPayload:
    records_verified: int = 0
    records_truncated: int = 0
    last_valid_seq: int = 0
    recovery_method: RecoveryMethod = RecoveryMethod.CHAIN_SCAN
    detail: str = ""


@dataclass
class KeyPayload:
    public_key: bytes = ZERO_HASH_32
    key_id: bytes = ZERO_HASH_32
    expires_at: int = 0
    supersedes_key_id: bytes = ZERO_HASH_32


@dataclass
class WitnessPayload:
    witness_id: str = ""
    checkpoint_seq: int = 0
    checkpoint_hash: bytes = ZERO_HASH_32
    witness_timestamp: int = 0
    receipt_signature: bytes = b"\x00" * 64
    witness_public_key: bytes = ZERO_HASH_32


# --- Record (Common Envelope + Payload) ---

Payload = Union[ActionPayload, GapPayload, CheckpointPayload, BootPayload, RecoveryPayload, KeyPayload, WitnessPayload]

PAYLOAD_TYPE_MAP = {
    ActionPayload: RecordType.ACTION,
    GapPayload: RecordType.GAP,
    CheckpointPayload: RecordType.CHECKPOINT,
    BootPayload: RecordType.BOOT,
    RecoveryPayload: RecordType.RECOVERY,
    KeyPayload: RecordType.KEY,
    WitnessPayload: RecordType.WITNESS,
}


@dataclass
class Record:
    record_id: bytes = ZERO_UUID  # 16 bytes UUID v7
    agent_id: bytes = ZERO_UUID
    session_id: bytes = ZERO_UUID
    timestamp_ms: int = 0
    sequence: int = 0
    prev_hash: bytes = ZERO_HASH_32
    schema_version: int = SCHEMA_VERSION
    record_type: RecordType = RecordType.ACTION
    payload: Payload = field(default_factory=ActionPayload)

    # Cached canonical bytes (set after serialization)
    _stored_bytes: Optional[bytes] = field(default=None, repr=False, compare=False)
