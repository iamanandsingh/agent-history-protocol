"""Input validation and security hardening for AHP records.

Validates record fields before serialization to prevent:
- Oversized payloads causing memory issues
- Invalid enum values corrupting the chain
- Malformed UUIDs or hashes
"""

from __future__ import annotations

from typing import List

from ahp.core.records import (
    ActionPayload,
    Authorization,
    BootPayload,
    CheckpointPayload,
    GapPayload,
    Record,
)
from ahp.core.types import (
    ActionType,
    AuthorizationDecision,
    AuthorizationType,
    AuthorizerType,
    ChainLevel,
    GapReason,
    Protocol,
    RecordType,
    ResultStatus,
)

# Limits
MAX_STRING_LENGTH = 65536  # 64KB per string field
MAX_TOOL_NAME_LENGTH = 1024
MAX_AUTH_ENTRIES = 100
MAX_INTERCEPTORS = 50
MAX_RECORD_SIZE = 1048576  # 1MB canonical bytes
MAX_UINT32 = (2**32) - 1
MAX_UINT64 = (2**64) - 1


class ValidationError(Exception):
    """Raised when a record fails validation."""

    pass


def validate_record(record: Record) -> List[str]:
    """Validate a record before serialization. Returns list of errors."""
    errors = []  # type: List[str]

    # Envelope validation
    if len(record.record_id) != 16:
        errors.append(f"record_id must be 16 bytes, got {len(record.record_id)}")
    if len(record.agent_id) != 16:
        errors.append(f"agent_id must be 16 bytes, got {len(record.agent_id)}")
    if len(record.session_id) != 16:
        errors.append(f"session_id must be 16 bytes, got {len(record.session_id)}")
    if len(record.prev_hash) != 32:
        errors.append(f"prev_hash must be 32 bytes, got {len(record.prev_hash)}")
    if record.sequence < 0:
        errors.append(f"sequence must be >= 0, got {record.sequence}")
    if record.timestamp_ms < 0:
        errors.append(f"timestamp_ms must be >= 0, got {record.timestamp_ms}")

    # Enum validation
    try:
        RecordType(record.record_type)
    except ValueError:
        errors.append(f"Invalid record_type: {record.record_type}")

    # Payload validation
    p = record.payload
    if isinstance(p, ActionPayload):
        errors.extend(_validate_action(p))
    elif isinstance(p, GapPayload):
        errors.extend(_validate_gap(p))
    elif isinstance(p, BootPayload):
        errors.extend(_validate_boot(p))
    elif isinstance(p, CheckpointPayload):
        errors.extend(_validate_checkpoint(p))

    return errors


def _validate_action(p: ActionPayload) -> List[str]:
    errors = []  # type: List[str]

    if len(p.tool_name.encode("utf-8")) > MAX_TOOL_NAME_LENGTH:
        errors.append(f"tool_name too long: {len(p.tool_name.encode('utf-8'))} > {MAX_TOOL_NAME_LENGTH}")
    if len(p.target_entity.encode("utf-8")) > MAX_STRING_LENGTH:
        errors.append(f"target_entity too long: {len(p.target_entity.encode('utf-8'))}")
    if len(p.evidence_uri.encode("utf-8")) > MAX_STRING_LENGTH:
        errors.append(f"evidence_uri too long: {len(p.evidence_uri.encode('utf-8'))}")
    if len(p.model_id.encode("utf-8")) > MAX_TOOL_NAME_LENGTH:
        errors.append(f"model_id too long: {len(p.model_id.encode('utf-8'))}")
    if len(p.provider.encode("utf-8")) > MAX_TOOL_NAME_LENGTH:
        errors.append(f"provider too long: {len(p.provider.encode('utf-8'))}")
    if p.cache_read_tokens < 0 or p.cache_read_tokens > MAX_UINT32:
        errors.append(f"cache_read_tokens must be 0..{MAX_UINT32}, got {p.cache_read_tokens}")
    if p.cache_creation_tokens < 0 or p.cache_creation_tokens > MAX_UINT32:
        errors.append(f"cache_creation_tokens must be 0..{MAX_UINT32}, got {p.cache_creation_tokens}")
    if p.reasoning_tokens < 0 or p.reasoning_tokens > MAX_UINT32:
        errors.append(f"reasoning_tokens must be 0..{MAX_UINT32}, got {p.reasoning_tokens}")
    if p.cost_nano_usd < 0 or p.cost_nano_usd > MAX_UINT64:
        errors.append(f"cost_nano_usd must be 0..{MAX_UINT64}, got {p.cost_nano_usd}")
    if len(p.parameters_hash) != 16:
        errors.append(f"parameters_hash must be 16 bytes, got {len(p.parameters_hash)}")
    if len(p.result_hash) != 16:
        errors.append(f"result_hash must be 16 bytes, got {len(p.result_hash)}")
    if len(p.parent_action_id) != 16:
        errors.append(f"parent_action_id must be 16 bytes, got {len(p.parent_action_id)}")

    # Enum validation
    try:
        ResultStatus(p.result_status)
    except ValueError:
        errors.append(f"Invalid result_status: {p.result_status}")
    try:
        Protocol(p.protocol)
    except ValueError:
        errors.append(f"Invalid protocol: {p.protocol}")
    try:
        ActionType(p.action_type)
    except ValueError:
        errors.append(f"Invalid action_type: {p.action_type}")

    # Authorization validation
    errors.extend(_validate_authorization(p.authorization))

    return errors


def _validate_authorization(auth: Authorization) -> List[str]:
    errors = []  # type: List[str]

    try:
        AuthorizationType(auth.type)
    except ValueError:
        errors.append(f"Invalid authorization type: {auth.type}")

    if len(auth.entries) > MAX_AUTH_ENTRIES:
        errors.append(f"Too many auth entries: {len(auth.entries)} > {MAX_AUTH_ENTRIES}")

    if auth.type == AuthorizationType.AUTH_NONE and len(auth.entries) > 0:
        errors.append("AUTH_NONE must have 0 entries")
    if auth.type == AuthorizationType.AUTH_MULTI_PARTY and len(auth.entries) < 2:
        errors.append("AUTH_MULTI_PARTY must have >= 2 entries")
    if (
        auth.type in (AuthorizationType.AUTH_HUMAN, AuthorizationType.AUTH_AGENT, AuthorizationType.AUTH_POLICY)
        and len(auth.entries) != 1
    ):
        errors.append(f"{auth.type.name} must have exactly 1 entry, got {len(auth.entries)}")

    for i, entry in enumerate(auth.entries):
        if len(entry.authorizer_id) > MAX_STRING_LENGTH:
            errors.append(f"auth entry {i}: authorizer_id too long")
        if len(entry.authorizer_agent_id) != 16:
            errors.append(f"auth entry {i}: authorizer_agent_id must be 16 bytes")
        try:
            AuthorizerType(entry.authorizer_type)
        except ValueError:
            errors.append(f"auth entry {i}: invalid authorizer_type: {entry.authorizer_type}")
        try:
            AuthorizationDecision(entry.decision)
        except ValueError:
            errors.append(f"auth entry {i}: invalid decision: {entry.decision}")

        if entry.authorizer_type == AuthorizerType.AUTHORIZER_AGENT:
            if entry.authorizer_agent_id == b"\x00" * 16:
                errors.append(f"auth entry {i}: AUTHORIZER_AGENT must have authorizer_agent_id set")

    return errors


def _validate_gap(p: GapPayload) -> List[str]:
    errors = []  # type: List[str]
    if p.count != p.last_lost_sequence - p.first_lost_sequence + 1:
        errors.append(f"GapPayload count mismatch: {p.count} != {p.last_lost_sequence - p.first_lost_sequence + 1}")
    if p.first_lost_sequence > p.last_lost_sequence:
        errors.append(f"first_lost > last_lost: {p.first_lost_sequence} > {p.last_lost_sequence}")
    try:
        GapReason(p.reason)
    except ValueError:
        errors.append(f"Invalid gap reason: {p.reason}")
    return errors


def _validate_boot(p: BootPayload) -> List[str]:
    errors = []  # type: List[str]
    if len(p.agent_name) > MAX_TOOL_NAME_LENGTH:
        errors.append(f"agent_name too long: {len(p.agent_name)}")
    if len(p.interceptors) > MAX_INTERCEPTORS:
        errors.append(f"Too many interceptors: {len(p.interceptors)}")
    if len(p.filter_config_hash) != 32:
        errors.append("filter_config_hash must be 32 bytes")
    try:
        ChainLevel(p.chain_level)
    except ValueError:
        errors.append(f"Invalid chain_level: {p.chain_level}")
    return errors


def _validate_checkpoint(p: CheckpointPayload) -> List[str]:
    errors = []  # type: List[str]
    if len(p.chain_hash) != 32:
        errors.append("chain_hash must be 32 bytes")
    if len(p.merkle_root) != 32:
        errors.append("merkle_root must be 32 bytes")
    if len(p.signature) != 64:
        errors.append("signature must be 64 bytes")
    if len(p.signing_key_id) != 32:
        errors.append("signing_key_id must be 32 bytes")
    return errors
