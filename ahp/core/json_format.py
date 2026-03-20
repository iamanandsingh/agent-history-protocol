"""JSON record format — Appendix H of the AHP specification.

Converts canonical binary records to human-readable JSON for display and export.
"""

from ahp.core.chain import (
    parse_action_payload,
    parse_boot_payload,
    parse_checkpoint_payload,
    parse_envelope,
    parse_gap_payload,
    parse_key_payload,
    parse_recovery_payload,
    parse_witness_payload,
)
from ahp.core.types import (
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
from ahp.core.uuid7 import uuid7_to_str


def _safe_enum_name(enum_cls, value, default: str = "UNKNOWN") -> str:
    """Convert an integer to an enum name, returning a fallback for invalid values."""
    try:
        return enum_cls(value).name
    except ValueError:
        return f"{default}({value})"


def record_to_json(stored_bytes: bytes) -> dict:
    """Convert canonical bytes to JSON-friendly dict per Appendix H."""
    env = parse_envelope(stored_bytes)

    result = {
        "record_id": uuid7_to_str(env["record_id"]),
        "agent_id": uuid7_to_str(env["agent_id"]),
        "session_id": uuid7_to_str(env["session_id"]),
        "timestamp_ms": env["timestamp_ms"],
        "sequence": env["sequence"],
        "prev_hash": env["prev_hash"].hex() if env["prev_hash"] != b"\x00" * 32 else None,
        "schema_version": env["schema_version"],
        "type": _safe_enum_name(RecordType, env["record_type"]),
    }

    rtype = env["record_type"]

    if rtype == RecordType.ACTION:
        payload = parse_action_payload(env["payload_bytes"])
        auth_entries = []
        for e in payload["authorization"]["entries"]:
            entry = {
                "authorizer_type": _safe_enum_name(AuthorizerType, e["authorizer_type"])
                if e["authorizer_type"]
                else None,
                "authorizer_id": e["authorizer_id"],
                "authorizer_agent_id": uuid7_to_str(e["authorizer_agent_id"])
                if e["authorizer_agent_id"] != ZERO_UUID
                else None,
                "authorizer_seq": e["authorizer_seq"] if e["authorizer_seq"] != 0 else None,
                "decision": _safe_enum_name(AuthorizationDecision, e["decision"]) if e["decision"] else None,
                "condition": e["condition"] or None,
                "timestamp_ms": e["timestamp_ms"],
            }
            auth_entries.append(entry)

        result["payload"] = {
            "parent_action_id": uuid7_to_str(payload["parent_action_id"])
            if payload["parent_action_id"] != ZERO_UUID
            else None,
            "tool_name": payload["tool_name"],
            "parameters_hash": payload["parameters_hash"].hex(),
            "result_hash": payload["result_hash"].hex(),
            "result_status": _safe_enum_name(ResultStatus, payload["result_status"]),
            "response_time_ms": payload["response_time_ms"],
            "protocol": _safe_enum_name(Protocol, payload["protocol"]),
            "action_type": _safe_enum_name(ActionType, payload["action_type"]),
            "target_entity": payload["target_entity"] or None,
            "evidence_uri": payload["evidence_uri"] or None,
            "redacted": payload["redacted"],
            "model_id": payload["model_id"] or None,
            "input_token_count": payload["input_token_count"],
            "output_token_count": payload["output_token_count"],
            "authorization": {
                "type": _safe_enum_name(AuthorizationType, payload["authorization"]["type"]),
                "entries": auth_entries,
            },
        }

    elif rtype == RecordType.BOOT:
        payload = parse_boot_payload(env["payload_bytes"])
        result["payload"] = {
            "sdk_name": payload["sdk_name"],
            "sdk_version": payload["sdk_version"],
            "interceptors": payload["interceptors"],
            "agent_framework": payload["agent_framework"] or None,
            "agent_name": payload["agent_name"],
            "runtime": payload["runtime"],
            "chain_level": _safe_enum_name(ChainLevel, payload["chain_level"]),
            "fsync_mode": _safe_enum_name(FsyncMode, payload["fsync_mode"]),
            "clock_source": payload["clock_source"] or None,
            "inference_recording": payload["inference_recording"],
            "inference_evidence": payload["inference_evidence"],
            "evidence_recording": payload["evidence_recording"],
            "filter_config_hash": payload["filter_config_hash"].hex(),
            "matched_agent_rule": payload["matched_agent_rule"] or None,
            "config_source": payload["config_source"] or None,
            "authorization_recording": payload["authorization_recording"],
        }

    elif rtype == RecordType.GAP:
        payload = parse_gap_payload(env["payload_bytes"])
        result["payload"] = {
            "first_lost_sequence": payload["first_lost_sequence"],
            "last_lost_sequence": payload["last_lost_sequence"],
            "count": payload["count"],
            "reason": _safe_enum_name(GapReason, payload["reason"]),
            "detail": payload["detail"] or None,
        }

    elif rtype == RecordType.CHECKPOINT:
        payload = parse_checkpoint_payload(env["payload_bytes"])
        result["payload"] = {
            "record_count": payload["record_count"],
            "gap_count": payload["gap_count"],
            "chain_hash": payload["chain_hash"].hex(),
            "merkle_root": payload["merkle_root"].hex(),
            "signature": payload["signature"].hex(),
            "signing_key_id": payload["signing_key_id"].hex(),
            "evidence_available": payload["evidence_available"],
            "evidence_exported": payload["evidence_exported"],
            "evidence_expired": payload["evidence_expired"],
            "evidence_missing": payload["evidence_missing"],
        }

    elif rtype == RecordType.RECOVERY:
        payload = parse_recovery_payload(env["payload_bytes"])
        result["payload"] = {
            "records_verified": payload["records_verified"],
            "records_truncated": payload["records_truncated"],
            "last_valid_seq": payload["last_valid_seq"],
            "recovery_method": _safe_enum_name(RecoveryMethod, payload["recovery_method"]),
            "detail": payload["detail"] or None,
        }

    elif rtype == RecordType.KEY:
        payload = parse_key_payload(env["payload_bytes"])
        result["payload"] = {
            "public_key": payload["public_key"].hex(),
            "key_id": payload["key_id"].hex(),
            "expires_at": payload["expires_at"],
            "supersedes_key_id": payload["supersedes_key_id"].hex(),
        }

    elif rtype == RecordType.WITNESS:
        payload = parse_witness_payload(env["payload_bytes"])
        result["payload"] = {
            "witness_id": payload["witness_id"],
            "checkpoint_seq": payload["checkpoint_seq"],
            "checkpoint_hash": payload["checkpoint_hash"].hex(),
            "witness_timestamp": payload["witness_timestamp"],
            "receipt_signature": payload["receipt_signature"].hex(),
            "witness_public_key": payload["witness_public_key"].hex(),
        }

    else:
        # Fallback for unknown types
        result["payload"] = {"raw": env["payload_bytes"].hex()}

    return result


def format_action_summary(stored_bytes: bytes) -> dict:
    """Compact summary of an ActionRecord for table display."""
    env = parse_envelope(stored_bytes)
    if env["record_type"] != RecordType.ACTION:
        return {
            "sequence": env["sequence"],
            "timestamp_ms": env["timestamp_ms"],
            "type": _safe_enum_name(RecordType, env["record_type"]),
            "protocol": "—",
            "tool_name": "—",
            "result_status": "—",
            "response_time_ms": 0,
            "action_type": "—",
            "authorization": "—",
        }

    payload = parse_action_payload(env["payload_bytes"])

    try:
        auth_type = AuthorizationType(payload["authorization"]["type"])
    except ValueError:
        auth_type = None

    # Build authorization display string
    if auth_type == AuthorizationType.AUTH_NONE:
        auth_display = "AUTH_NONE"
    elif auth_type == AuthorizationType.AUTH_HUMAN:
        entries = payload["authorization"]["entries"]
        name = entries[0]["authorizer_id"] if entries else "?"
        auth_display = f"\U0001f464 {name}"
    elif auth_type == AuthorizationType.AUTH_AGENT:
        entries = payload["authorization"]["entries"]
        name = entries[0]["authorizer_id"] if entries else "?"
        auth_display = f"\U0001f916 {name}"
    elif auth_type == AuthorizationType.AUTH_POLICY:
        entries = payload["authorization"]["entries"]
        name = entries[0]["authorizer_id"] if entries else "?"
        auth_display = f"\U0001f6e1 {name}"
    elif auth_type == AuthorizationType.AUTH_MULTI_PARTY:
        auth_display = "\U0001f464+\U0001f916 MULTI_PARTY"
    else:
        auth_display = "?"

    return {
        "sequence": env["sequence"],
        "timestamp_ms": env["timestamp_ms"],
        "type": _safe_enum_name(ActionType, payload["action_type"]),
        "protocol": _safe_enum_name(Protocol, payload["protocol"]),
        "tool_name": payload["tool_name"],
        "result_status": _safe_enum_name(ResultStatus, payload["result_status"]),
        "response_time_ms": payload["response_time_ms"],
        "authorization": auth_display,
        "model_id": payload["model_id"],
    }
