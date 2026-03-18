"""Canonical serialization — deterministic byte representation for hashing.

Implements Section 4 of the AHP specification. Every field is serialized in
strictly ascending tag order with fixed-width little-endian integers, length-
prefixed UTF-8 strings, and raw UUID bytes. This produces identical output
across all implementations for the same logical record.
"""

import struct
from ahp.core.types import RecordType
from ahp.core.records import (
    Record, ActionPayload, GapPayload, CheckpointPayload,
    BootPayload, RecoveryPayload, KeyPayload, WitnessPayload,
)


def canonical_bytes(record: Record) -> bytes:
    """Serialize a record to canonical bytes for hashing and storage."""
    buf = bytearray()

    # --- Envelope (ascending tag order) ---
    buf += record.record_id                            # tag 1: 16 bytes UUID
    buf += record.agent_id                             # tag 2: 16 bytes UUID
    buf += record.session_id                           # tag 3: 16 bytes UUID
    buf += _uint64(record.timestamp_ms)                # tag 4: 8 bytes
    buf += _uint64(record.sequence)                    # tag 5: 8 bytes
    buf += record.prev_hash                            # tag 6: 32 bytes
    buf += _uint32(record.schema_version)              # tag 7: 4 bytes
    buf += _uint32(record.record_type)                 # tag 8: 4 bytes enum

    # --- Payload type discriminator ---
    buf += _uint32(record.record_type)                 # payload type tag

    # --- Payload fields (ascending tag order per type) ---
    p = record.payload
    if isinstance(p, ActionPayload):
        _serialize_action(buf, p)
    elif isinstance(p, GapPayload):
        _serialize_gap(buf, p)
    elif isinstance(p, CheckpointPayload):
        _serialize_checkpoint(buf, p)
    elif isinstance(p, BootPayload):
        _serialize_boot(buf, p)
    elif isinstance(p, RecoveryPayload):
        _serialize_recovery(buf, p)
    elif isinstance(p, KeyPayload):
        _serialize_key(buf, p)
    elif isinstance(p, WitnessPayload):
        _serialize_witness(buf, p)
    else:
        raise ValueError(f"Unknown payload type: {type(p)}")

    return bytes(buf)


def _serialize_action(buf: bytearray, p: ActionPayload) -> None:
    buf += p.parent_action_id                          # tag 1: 16 bytes UUID
    _append_string(buf, p.tool_name)                   # tag 2
    buf += p.parameters_hash                           # tag 3: 16 bytes
    buf += p.result_hash                               # tag 4: 16 bytes
    buf += _uint32(p.result_status)                    # tag 5: enum
    buf += _uint32(p.response_time_ms)                 # tag 6
    buf += _uint32(p.protocol)                         # tag 7: enum
    buf += _uint32(p.action_type)                      # tag 8: enum
    _append_string(buf, p.target_entity)               # tag 9
    _append_string(buf, p.evidence_uri)                # tag 10
    buf += _bool(p.redacted)                           # tag 11
    _append_string(buf, p.model_id)                    # tag 12
    buf += _uint32(p.input_token_count)                # tag 13
    buf += _uint32(p.output_token_count)               # tag 14
    # tag 15: Authorization (nested, inline)
    buf += _uint32(p.authorization.type)               # tag 15.1: enum
    buf += _uint32(len(p.authorization.entries))        # tag 15.2: count
    for entry in p.authorization.entries:
        buf += _uint32(entry.authorizer_type)           # tag 15.2.1: enum
        _append_string(buf, entry.authorizer_id)        # tag 15.2.2
        buf += entry.authorizer_agent_id                # tag 15.2.3: 16 bytes UUID
        buf += _uint64(entry.authorizer_seq)            # tag 15.2.4
        buf += _uint32(entry.decision)                  # tag 15.2.5: enum
        _append_string(buf, entry.condition)             # tag 15.2.6
        buf += _uint64(entry.timestamp_ms)              # tag 15.2.7


def _serialize_gap(buf: bytearray, p: GapPayload) -> None:
    buf += _uint64(p.first_lost_sequence)              # tag 1
    buf += _uint64(p.last_lost_sequence)               # tag 2
    buf += _uint64(p.count)                            # tag 3
    buf += _uint32(p.reason)                           # tag 4: enum
    _append_string(buf, p.detail)                      # tag 5


def _serialize_checkpoint(buf: bytearray, p: CheckpointPayload) -> None:
    buf += _uint64(p.record_count)                     # tag 1
    buf += _uint64(p.gap_count)                        # tag 2
    buf += p.chain_hash                                # tag 3: 32 bytes
    buf += p.merkle_root                               # tag 4: 32 bytes
    buf += p.signature                                 # tag 5: 64 bytes
    buf += p.signing_key_id                            # tag 6: 32 bytes
    # tag 7: EvidenceStatus (nested, inline)
    buf += _uint64(p.evidence_available)               # tag 7.1
    buf += _uint64(p.evidence_exported)                # tag 7.2
    buf += _uint64(p.evidence_expired)                 # tag 7.3
    buf += _uint64(p.evidence_missing)                 # tag 7.4


def _serialize_boot(buf: bytearray, p: BootPayload) -> None:
    _append_string(buf, p.sdk_name)                    # tag 1
    _append_string(buf, p.sdk_version)                 # tag 2
    # tag 3: repeated string (interceptors)
    buf += _uint32(len(p.interceptors))
    for s in p.interceptors:
        _append_string(buf, s)
    _append_string(buf, p.agent_framework)             # tag 4
    _append_string(buf, p.agent_name)                  # tag 5
    _append_string(buf, p.runtime)                     # tag 6
    buf += _uint32(p.chain_level)                      # tag 7: enum
    buf += _uint32(p.fsync_mode)                       # tag 8: enum
    _append_string(buf, p.clock_source)                # tag 9
    buf += _bool(p.inference_recording)                # tag 10
    buf += _bool(p.inference_evidence)                 # tag 11
    buf += _bool(p.evidence_recording)                 # tag 12
    buf += p.filter_config_hash                        # tag 13: 32 bytes
    _append_string(buf, p.matched_agent_rule)          # tag 14
    _append_string(buf, p.config_source)               # tag 15
    buf += _bool(p.authorization_recording)            # tag 16


def _serialize_recovery(buf: bytearray, p: RecoveryPayload) -> None:
    buf += _uint64(p.records_verified)                 # tag 1
    buf += _uint64(p.records_truncated)                # tag 2
    buf += _uint64(p.last_valid_seq)                   # tag 3
    buf += _uint32(p.recovery_method)                  # tag 4: enum
    _append_string(buf, p.detail)                      # tag 5


def _serialize_key(buf: bytearray, p: KeyPayload) -> None:
    buf += p.public_key                                # tag 1: 32 bytes
    buf += p.key_id                                    # tag 2: 32 bytes
    buf += _uint64(p.expires_at)                       # tag 3
    buf += p.supersedes_key_id                         # tag 4: 32 bytes


def _serialize_witness(buf: bytearray, p: WitnessPayload) -> None:
    _append_string(buf, p.witness_id)                  # tag 1
    buf += _uint64(p.checkpoint_seq)                   # tag 2
    buf += p.checkpoint_hash                           # tag 3: 32 bytes
    buf += _uint64(p.witness_timestamp)                # tag 4
    buf += p.receipt_signature                         # tag 5: 64 bytes
    buf += p.witness_public_key                        # tag 6: 32 bytes


# --- Primitive serialization helpers ---

def _uint32(value: int) -> bytes:
    """Fixed-width 4-byte little-endian unsigned integer."""
    return struct.pack('<I', value)


def _uint64(value: int) -> bytes:
    """Fixed-width 8-byte little-endian unsigned integer."""
    return struct.pack('<Q', value)


def _bool(value: bool) -> bytes:
    """Single byte: 0x00 = false, 0x01 = true."""
    return b'\x01' if value else b'\x00'


def _append_string(buf: bytearray, s: str) -> None:
    """UTF-8 bytes with uint32 length prefix."""
    encoded = s.encode('utf-8')
    buf += _uint32(len(encoded))
    buf += encoded
