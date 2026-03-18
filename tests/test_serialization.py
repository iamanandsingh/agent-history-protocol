"""Comprehensive canonical serialization tests — all 7 payload types."""
from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from typing import Optional, List, Dict

from ahp.core.types import (
    RecordType, ResultStatus, Protocol, ActionType,
    AuthorizationType, AuthorizerType, AuthorizationDecision,
    GapReason, ChainLevel, FsyncMode, RecoveryMethod,
    ZERO_HASH_32, ZERO_HASH_16, ZERO_UUID, SCHEMA_VERSION,
)
from ahp.core.records import (
    Record, ActionPayload, BootPayload, GapPayload,
    CheckpointPayload, RecoveryPayload, KeyPayload, WitnessPayload,
    Authorization, AuthorizationEntry, PAYLOAD_TYPE_MAP,
)
from ahp.core.canonical import canonical_bytes
from ahp.core.chain import (
    ChainWriter, ChainReader, parse_envelope,
    parse_action_payload, parse_boot_payload, parse_gap_payload,
    parse_checkpoint_payload, parse_recovery_payload,
    parse_key_payload, parse_witness_payload,
)
from ahp.core.json_format import record_to_json


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_record(payload, record_type: RecordType, **overrides) -> Record:
    """Build a Record with deterministic envelope fields."""
    fields = dict(
        record_id=b'\x01' * 16,
        agent_id=b'\x02' * 16,
        session_id=b'\x03' * 16,
        timestamp_ms=1710000000000,
        sequence=1,
        prev_hash=ZERO_HASH_32,
        schema_version=SCHEMA_VERSION,
        record_type=record_type,
        payload=payload,
    )
    fields.update(overrides)
    return Record(**fields)


def _roundtrip_envelope(record: Record) -> dict:
    """Serialize then parse envelope, return parsed dict."""
    stored = canonical_bytes(record)
    return parse_envelope(stored)


# ===================================================================
# 1. Round-trip tests for each of the 7 payload types
# ===================================================================

class TestActionRoundTrip(unittest.TestCase):
    """ACTION payload: serialize -> parse -> assert fields match -> re-serialize identical."""

    def test_round_trip(self):
        payload = ActionPayload(
            parent_action_id=b'\x10' * 16,
            tool_name="read_file",
            parameters_hash=b'\xaa' * 16,
            result_hash=b'\xbb' * 16,
            result_status=ResultStatus.SUCCESS,
            response_time_ms=42,
            protocol=Protocol.MCP,
            action_type=ActionType.TOOL_CALL,
            target_entity="file:///tmp/test.txt",
            evidence_uri="evidence://abc123",
            redacted=False,
            model_id="claude-3-opus",
            input_token_count=100,
            output_token_count=200,
            authorization=Authorization(
                type=AuthorizationType.AUTH_HUMAN,
                entries=[AuthorizationEntry(
                    authorizer_type=AuthorizerType.AUTHORIZER_HUMAN,
                    authorizer_id="user:alice",
                    authorizer_agent_id=b'\x04' * 16,
                    authorizer_seq=5,
                    decision=AuthorizationDecision.APPROVED,
                    condition="budget < 100",
                    timestamp_ms=1710000000001,
                )],
            ),
        )
        record = _make_record(payload, RecordType.ACTION)
        stored = canonical_bytes(record)
        env = parse_envelope(stored)
        parsed = parse_action_payload(env['payload_bytes'])

        # Assert every field
        self.assertEqual(parsed['parent_action_id'], b'\x10' * 16)
        self.assertEqual(parsed['tool_name'], "read_file")
        self.assertEqual(parsed['parameters_hash'], b'\xaa' * 16)
        self.assertEqual(parsed['result_hash'], b'\xbb' * 16)
        self.assertEqual(parsed['result_status'], ResultStatus.SUCCESS)
        self.assertEqual(parsed['response_time_ms'], 42)
        self.assertEqual(parsed['protocol'], Protocol.MCP)
        self.assertEqual(parsed['action_type'], ActionType.TOOL_CALL)
        self.assertEqual(parsed['target_entity'], "file:///tmp/test.txt")
        self.assertEqual(parsed['evidence_uri'], "evidence://abc123")
        self.assertFalse(parsed['redacted'])
        self.assertEqual(parsed['model_id'], "claude-3-opus")
        self.assertEqual(parsed['input_token_count'], 100)
        self.assertEqual(parsed['output_token_count'], 200)
        self.assertEqual(parsed['authorization']['type'], AuthorizationType.AUTH_HUMAN)
        self.assertEqual(len(parsed['authorization']['entries']), 1)

        entry = parsed['authorization']['entries'][0]
        self.assertEqual(entry['authorizer_type'], AuthorizerType.AUTHORIZER_HUMAN)
        self.assertEqual(entry['authorizer_id'], "user:alice")
        self.assertEqual(entry['authorizer_agent_id'], b'\x04' * 16)
        self.assertEqual(entry['authorizer_seq'], 5)
        self.assertEqual(entry['decision'], AuthorizationDecision.APPROVED)
        self.assertEqual(entry['condition'], "budget < 100")
        self.assertEqual(entry['timestamp_ms'], 1710000000001)

        # Re-serialize -> identical bytes
        stored2 = canonical_bytes(record)
        self.assertEqual(stored, stored2)


class TestBootRoundTrip(unittest.TestCase):
    """BOOT payload round-trip."""

    def test_round_trip(self):
        payload = BootPayload(
            sdk_name="ahp-python",
            sdk_version="0.1.0",
            interceptors=["mcp_interceptor", "http_interceptor"],
            agent_framework="langchain",
            agent_name="test-agent",
            runtime="cpython-3.11",
            chain_level=ChainLevel.LEVEL_2,
            fsync_mode=FsyncMode.EVERY,
            clock_source="system",
            inference_recording=True,
            inference_evidence=True,
            evidence_recording=False,
            filter_config_hash=b'\xcc' * 32,
            matched_agent_rule="rule:default",
            config_source="config.yaml",
            authorization_recording=True,
        )
        record = _make_record(payload, RecordType.BOOT)
        stored = canonical_bytes(record)
        env = parse_envelope(stored)
        parsed = parse_boot_payload(env['payload_bytes'])

        self.assertEqual(parsed['sdk_name'], "ahp-python")
        self.assertEqual(parsed['sdk_version'], "0.1.0")
        self.assertEqual(parsed['interceptors'], ["mcp_interceptor", "http_interceptor"])
        self.assertEqual(parsed['agent_framework'], "langchain")
        self.assertEqual(parsed['agent_name'], "test-agent")
        self.assertEqual(parsed['runtime'], "cpython-3.11")
        self.assertEqual(parsed['chain_level'], ChainLevel.LEVEL_2)
        self.assertEqual(parsed['fsync_mode'], FsyncMode.EVERY)
        self.assertEqual(parsed['clock_source'], "system")
        self.assertTrue(parsed['inference_recording'])
        self.assertTrue(parsed['inference_evidence'])
        self.assertFalse(parsed['evidence_recording'])
        self.assertEqual(parsed['filter_config_hash'], b'\xcc' * 32)
        self.assertEqual(parsed['matched_agent_rule'], "rule:default")
        self.assertEqual(parsed['config_source'], "config.yaml")
        self.assertTrue(parsed['authorization_recording'])

        # Re-serialize -> identical bytes
        stored2 = canonical_bytes(record)
        self.assertEqual(stored, stored2)


class TestGapRoundTrip(unittest.TestCase):
    """GAP payload round-trip."""

    def test_round_trip(self):
        payload = GapPayload(
            first_lost_sequence=10,
            last_lost_sequence=15,
            count=6,
            reason=GapReason.CRASH,
            detail="Process killed by OOM",
        )
        record = _make_record(payload, RecordType.GAP)
        stored = canonical_bytes(record)
        env = parse_envelope(stored)
        parsed = parse_gap_payload(env['payload_bytes'])

        self.assertEqual(parsed['first_lost_sequence'], 10)
        self.assertEqual(parsed['last_lost_sequence'], 15)
        self.assertEqual(parsed['count'], 6)
        self.assertEqual(parsed['reason'], GapReason.CRASH)
        self.assertEqual(parsed['detail'], "Process killed by OOM")

        # Re-serialize -> identical bytes
        stored2 = canonical_bytes(record)
        self.assertEqual(stored, stored2)


class TestCheckpointRoundTrip(unittest.TestCase):
    """CHECKPOINT payload round-trip."""

    def test_round_trip(self):
        payload = CheckpointPayload(
            record_count=500,
            gap_count=2,
            chain_hash=b'\xdd' * 32,
            merkle_root=b'\xee' * 32,
            signature=b'\xff' * 64,
            signing_key_id=b'\x11' * 32,
            evidence_available=100,
            evidence_exported=80,
            evidence_expired=10,
            evidence_missing=10,
        )
        record = _make_record(payload, RecordType.CHECKPOINT)
        stored = canonical_bytes(record)
        env = parse_envelope(stored)
        parsed = parse_checkpoint_payload(env['payload_bytes'])

        self.assertEqual(parsed['record_count'], 500)
        self.assertEqual(parsed['gap_count'], 2)
        self.assertEqual(parsed['chain_hash'], b'\xdd' * 32)
        self.assertEqual(parsed['merkle_root'], b'\xee' * 32)
        self.assertEqual(parsed['signature'], b'\xff' * 64)
        self.assertEqual(parsed['signing_key_id'], b'\x11' * 32)
        self.assertEqual(parsed['evidence_available'], 100)
        self.assertEqual(parsed['evidence_exported'], 80)
        self.assertEqual(parsed['evidence_expired'], 10)
        self.assertEqual(parsed['evidence_missing'], 10)

        # Re-serialize -> identical bytes
        stored2 = canonical_bytes(record)
        self.assertEqual(stored, stored2)


class TestRecoveryRoundTrip(unittest.TestCase):
    """RECOVERY payload round-trip."""

    def test_round_trip(self):
        payload = RecoveryPayload(
            records_verified=450,
            records_truncated=50,
            last_valid_seq=450,
            recovery_method=RecoveryMethod.CHAIN_SCAN,
            detail="Recovered from crash",
        )
        record = _make_record(payload, RecordType.RECOVERY)
        stored = canonical_bytes(record)
        env = parse_envelope(stored)
        parsed = parse_recovery_payload(env['payload_bytes'])

        self.assertEqual(parsed['records_verified'], 450)
        self.assertEqual(parsed['records_truncated'], 50)
        self.assertEqual(parsed['last_valid_seq'], 450)
        self.assertEqual(parsed['recovery_method'], RecoveryMethod.CHAIN_SCAN)
        self.assertEqual(parsed['detail'], "Recovered from crash")

        # Re-serialize -> identical bytes
        stored2 = canonical_bytes(record)
        self.assertEqual(stored, stored2)


class TestKeyRoundTrip(unittest.TestCase):
    """KEY payload round-trip."""

    def test_round_trip(self):
        payload = KeyPayload(
            public_key=b'\xaa' * 32,
            key_id=b'\xbb' * 32,
            expires_at=1720000000000,
            supersedes_key_id=b'\xcc' * 32,
        )
        record = _make_record(payload, RecordType.KEY)
        stored = canonical_bytes(record)
        env = parse_envelope(stored)
        parsed = parse_key_payload(env['payload_bytes'])

        self.assertEqual(parsed['public_key'], b'\xaa' * 32)
        self.assertEqual(parsed['key_id'], b'\xbb' * 32)
        self.assertEqual(parsed['expires_at'], 1720000000000)
        self.assertEqual(parsed['supersedes_key_id'], b'\xcc' * 32)

        # Re-serialize -> identical bytes
        stored2 = canonical_bytes(record)
        self.assertEqual(stored, stored2)


class TestWitnessRoundTrip(unittest.TestCase):
    """WITNESS payload round-trip."""

    def test_round_trip(self):
        payload = WitnessPayload(
            witness_id="witness-service-1",
            checkpoint_seq=100,
            checkpoint_hash=b'\xdd' * 32,
            witness_timestamp=1710000005000,
            receipt_signature=b'\xee' * 64,
            witness_public_key=b'\xff' * 32,
        )
        record = _make_record(payload, RecordType.WITNESS)
        stored = canonical_bytes(record)
        env = parse_envelope(stored)
        parsed = parse_witness_payload(env['payload_bytes'])

        self.assertEqual(parsed['witness_id'], "witness-service-1")
        self.assertEqual(parsed['checkpoint_seq'], 100)
        self.assertEqual(parsed['checkpoint_hash'], b'\xdd' * 32)
        self.assertEqual(parsed['witness_timestamp'], 1710000005000)
        self.assertEqual(parsed['receipt_signature'], b'\xee' * 64)
        self.assertEqual(parsed['witness_public_key'], b'\xff' * 32)

        # Re-serialize -> identical bytes
        stored2 = canonical_bytes(record)
        self.assertEqual(stored, stored2)


# ===================================================================
# 2. Edge case tests
# ===================================================================

class TestEdgeCases(unittest.TestCase):
    """Edge cases: empty strings, max integers, unicode, long strings."""

    def test_empty_strings_action(self):
        """ActionPayload with every string field empty."""
        payload = ActionPayload(
            tool_name="",
            target_entity="",
            evidence_uri="",
            model_id="",
            authorization=Authorization(
                type=AuthorizationType.AUTH_NONE,
                entries=[],
            ),
        )
        record = _make_record(payload, RecordType.ACTION)
        stored = canonical_bytes(record)
        env = parse_envelope(stored)
        parsed = parse_action_payload(env['payload_bytes'])

        self.assertEqual(parsed['tool_name'], "")
        self.assertEqual(parsed['target_entity'], "")
        self.assertEqual(parsed['evidence_uri'], "")
        self.assertEqual(parsed['model_id'], "")

    def test_empty_strings_boot(self):
        """BootPayload with every string field empty."""
        payload = BootPayload(
            sdk_name="",
            sdk_version="",
            interceptors=[],
            agent_framework="",
            agent_name="",
            runtime="",
            clock_source="",
            matched_agent_rule="",
            config_source="",
        )
        record = _make_record(payload, RecordType.BOOT)
        stored = canonical_bytes(record)
        env = parse_envelope(stored)
        parsed = parse_boot_payload(env['payload_bytes'])

        self.assertEqual(parsed['sdk_name'], "")
        self.assertEqual(parsed['sdk_version'], "")
        self.assertEqual(parsed['interceptors'], [])
        self.assertEqual(parsed['agent_framework'], "")
        self.assertEqual(parsed['agent_name'], "")
        self.assertEqual(parsed['runtime'], "")
        self.assertEqual(parsed['clock_source'], "")
        self.assertEqual(parsed['matched_agent_rule'], "")
        self.assertEqual(parsed['config_source'], "")

    def test_empty_strings_gap(self):
        """GapPayload with empty detail."""
        payload = GapPayload(
            first_lost_sequence=1,
            last_lost_sequence=1,
            count=1,
            reason=GapReason.CRASH,
            detail="",
        )
        record = _make_record(payload, RecordType.GAP)
        stored = canonical_bytes(record)
        env = parse_envelope(stored)
        parsed = parse_gap_payload(env['payload_bytes'])

        self.assertEqual(parsed['detail'], "")

    def test_empty_strings_recovery(self):
        """RecoveryPayload with empty detail."""
        payload = RecoveryPayload(
            records_verified=0,
            records_truncated=0,
            last_valid_seq=0,
            recovery_method=RecoveryMethod.FRESH_START,
            detail="",
        )
        record = _make_record(payload, RecordType.RECOVERY)
        stored = canonical_bytes(record)
        env = parse_envelope(stored)
        parsed = parse_recovery_payload(env['payload_bytes'])

        self.assertEqual(parsed['detail'], "")

    def test_empty_strings_witness(self):
        """WitnessPayload with empty witness_id."""
        payload = WitnessPayload(witness_id="")
        record = _make_record(payload, RecordType.WITNESS)
        stored = canonical_bytes(record)
        env = parse_envelope(stored)
        parsed = parse_witness_payload(env['payload_bytes'])

        self.assertEqual(parsed['witness_id'], "")

    def test_max_uint32(self):
        """Max uint32 (4294967295) in fields that use uint32."""
        payload = ActionPayload(
            response_time_ms=4294967295,
            input_token_count=4294967295,
            output_token_count=4294967295,
            authorization=Authorization(type=AuthorizationType.AUTH_NONE),
        )
        record = _make_record(payload, RecordType.ACTION, schema_version=4294967295)
        stored = canonical_bytes(record)
        env = parse_envelope(stored)
        parsed = parse_action_payload(env['payload_bytes'])

        self.assertEqual(env['schema_version'], 4294967295)
        self.assertEqual(parsed['response_time_ms'], 4294967295)
        self.assertEqual(parsed['input_token_count'], 4294967295)
        self.assertEqual(parsed['output_token_count'], 4294967295)

    def test_max_uint64(self):
        """Max uint64 (18446744073709551615) in fields that use uint64."""
        max_u64 = 18446744073709551615
        payload = GapPayload(
            first_lost_sequence=max_u64,
            last_lost_sequence=max_u64,
            count=max_u64,
            reason=GapReason.CRASH,
            detail="max test",
        )
        record = _make_record(payload, RecordType.GAP, timestamp_ms=max_u64, sequence=max_u64)
        stored = canonical_bytes(record)
        env = parse_envelope(stored)
        parsed = parse_gap_payload(env['payload_bytes'])

        self.assertEqual(env['timestamp_ms'], max_u64)
        self.assertEqual(env['sequence'], max_u64)
        self.assertEqual(parsed['first_lost_sequence'], max_u64)
        self.assertEqual(parsed['last_lost_sequence'], max_u64)
        self.assertEqual(parsed['count'], max_u64)

    def test_auth_none_zero_entries(self):
        """Authorization with AUTH_NONE and 0 entries."""
        payload = ActionPayload(
            tool_name="test",
            authorization=Authorization(
                type=AuthorizationType.AUTH_NONE,
                entries=[],
            ),
        )
        record = _make_record(payload, RecordType.ACTION)
        stored = canonical_bytes(record)
        env = parse_envelope(stored)
        parsed = parse_action_payload(env['payload_bytes'])

        self.assertEqual(parsed['authorization']['type'], AuthorizationType.AUTH_NONE)
        self.assertEqual(len(parsed['authorization']['entries']), 0)

    def test_auth_multi_party_three_entries(self):
        """Authorization with AUTH_MULTI_PARTY and 3 entries."""
        entries = [
            AuthorizationEntry(
                authorizer_type=AuthorizerType.AUTHORIZER_HUMAN,
                authorizer_id="user:alice",
                authorizer_agent_id=b'\x04' * 16,
                authorizer_seq=1,
                decision=AuthorizationDecision.APPROVED,
                condition="",
                timestamp_ms=1710000000001,
            ),
            AuthorizationEntry(
                authorizer_type=AuthorizerType.AUTHORIZER_AGENT,
                authorizer_id="agent:safety-checker",
                authorizer_agent_id=b'\x05' * 16,
                authorizer_seq=2,
                decision=AuthorizationDecision.CONDITIONAL,
                condition="risk_score < 0.5",
                timestamp_ms=1710000000002,
            ),
            AuthorizationEntry(
                authorizer_type=AuthorizerType.AUTHORIZER_POLICY_ENGINE,
                authorizer_id="policy:corporate-v2",
                authorizer_agent_id=b'\x06' * 16,
                authorizer_seq=3,
                decision=AuthorizationDecision.APPROVED,
                condition="",
                timestamp_ms=1710000000003,
            ),
        ]
        payload = ActionPayload(
            tool_name="deploy",
            authorization=Authorization(
                type=AuthorizationType.AUTH_MULTI_PARTY,
                entries=entries,
            ),
        )
        record = _make_record(payload, RecordType.ACTION)
        stored = canonical_bytes(record)
        env = parse_envelope(stored)
        parsed = parse_action_payload(env['payload_bytes'])

        self.assertEqual(parsed['authorization']['type'], AuthorizationType.AUTH_MULTI_PARTY)
        self.assertEqual(len(parsed['authorization']['entries']), 3)

        pe = parsed['authorization']['entries']
        self.assertEqual(pe[0]['authorizer_id'], "user:alice")
        self.assertEqual(pe[0]['authorizer_type'], AuthorizerType.AUTHORIZER_HUMAN)
        self.assertEqual(pe[1]['authorizer_id'], "agent:safety-checker")
        self.assertEqual(pe[1]['decision'], AuthorizationDecision.CONDITIONAL)
        self.assertEqual(pe[1]['condition'], "risk_score < 0.5")
        self.assertEqual(pe[2]['authorizer_id'], "policy:corporate-v2")
        self.assertEqual(pe[2]['authorizer_type'], AuthorizerType.AUTHORIZER_POLICY_ENGINE)

        # Re-serialize -> identical
        stored2 = canonical_bytes(record)
        self.assertEqual(stored, stored2)

    def test_unicode_japanese(self):
        """Unicode strings with Japanese characters."""
        payload = ActionPayload(
            tool_name="\u3053\u3093\u306b\u3061\u306f",
            target_entity="\u3053\u3093\u306b\u3061\u306f",
            model_id="\u3053\u3093\u306b\u3061\u306f",
            authorization=Authorization(type=AuthorizationType.AUTH_NONE),
        )
        record = _make_record(payload, RecordType.ACTION)
        stored = canonical_bytes(record)
        env = parse_envelope(stored)
        parsed = parse_action_payload(env['payload_bytes'])

        self.assertEqual(parsed['tool_name'], "\u3053\u3093\u306b\u3061\u306f")
        self.assertEqual(parsed['target_entity'], "\u3053\u3093\u306b\u3061\u306f")
        self.assertEqual(parsed['model_id'], "\u3053\u3093\u306b\u3061\u306f")

    def test_unicode_emoji(self):
        """Unicode strings with emoji."""
        payload = GapPayload(
            first_lost_sequence=1,
            last_lost_sequence=1,
            count=1,
            reason=GapReason.CRASH,
            detail="\U0001f527 tool",
        )
        record = _make_record(payload, RecordType.GAP)
        stored = canonical_bytes(record)
        env = parse_envelope(stored)
        parsed = parse_gap_payload(env['payload_bytes'])

        self.assertEqual(parsed['detail'], "\U0001f527 tool")

    def test_unicode_accented(self):
        """Unicode strings with accented characters."""
        payload = RecoveryPayload(
            records_verified=10,
            records_truncated=0,
            last_valid_seq=10,
            recovery_method=RecoveryMethod.CHAIN_SCAN,
            detail="donn\u00e9es",
        )
        record = _make_record(payload, RecordType.RECOVERY)
        stored = canonical_bytes(record)
        env = parse_envelope(stored)
        parsed = parse_recovery_payload(env['payload_bytes'])

        self.assertEqual(parsed['detail'], "donn\u00e9es")

    def test_very_long_string(self):
        """String with 1000 characters."""
        long_str = "A" * 1000
        payload = ActionPayload(
            tool_name=long_str,
            authorization=Authorization(type=AuthorizationType.AUTH_NONE),
        )
        record = _make_record(payload, RecordType.ACTION)
        stored = canonical_bytes(record)
        env = parse_envelope(stored)
        parsed = parse_action_payload(env['payload_bytes'])

        self.assertEqual(parsed['tool_name'], long_str)
        self.assertEqual(len(parsed['tool_name']), 1000)

    def test_gap_single_lost_record(self):
        """GapPayload with count=1 (single lost record)."""
        payload = GapPayload(
            first_lost_sequence=42,
            last_lost_sequence=42,
            count=1,
            reason=GapReason.BACKPRESSURE,
            detail="single record lost",
        )
        record = _make_record(payload, RecordType.GAP)
        stored = canonical_bytes(record)
        env = parse_envelope(stored)
        parsed = parse_gap_payload(env['payload_bytes'])

        self.assertEqual(parsed['first_lost_sequence'], 42)
        self.assertEqual(parsed['last_lost_sequence'], 42)
        self.assertEqual(parsed['count'], 1)
        self.assertEqual(parsed['reason'], GapReason.BACKPRESSURE)

    def test_checkpoint_all_zeros(self):
        """CheckpointPayload with all default/zero values."""
        payload = CheckpointPayload(
            record_count=0,
            gap_count=0,
            chain_hash=ZERO_HASH_32,
            merkle_root=ZERO_HASH_32,
            signature=b'\x00' * 64,
            signing_key_id=ZERO_HASH_32,
            evidence_available=0,
            evidence_exported=0,
            evidence_expired=0,
            evidence_missing=0,
        )
        record = _make_record(payload, RecordType.CHECKPOINT)
        stored = canonical_bytes(record)
        env = parse_envelope(stored)
        parsed = parse_checkpoint_payload(env['payload_bytes'])

        self.assertEqual(parsed['record_count'], 0)
        self.assertEqual(parsed['gap_count'], 0)
        self.assertEqual(parsed['chain_hash'], ZERO_HASH_32)
        self.assertEqual(parsed['merkle_root'], ZERO_HASH_32)
        self.assertEqual(parsed['signature'], b'\x00' * 64)
        self.assertEqual(parsed['signing_key_id'], ZERO_HASH_32)
        self.assertEqual(parsed['evidence_available'], 0)
        self.assertEqual(parsed['evidence_exported'], 0)
        self.assertEqual(parsed['evidence_expired'], 0)
        self.assertEqual(parsed['evidence_missing'], 0)


# ===================================================================
# 3. JSON format tests for all 7 types
# ===================================================================

class TestJsonFormatAllTypes(unittest.TestCase):
    """record_to_json() must handle all 7 record types."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.chain_path = os.path.join(self.tmpdir, "test.ahp")

    def _write_and_read(self, payload) -> dict:
        """Write one record via ChainWriter, read back, return JSON dict."""
        writer = ChainWriter(self.chain_path)
        writer.write_record(payload)
        reader = ChainReader(self.chain_path)
        records = reader.read_all()
        return record_to_json(records[0])

    def test_action_json(self):
        j = self._write_and_read(ActionPayload(
            tool_name="test_tool",
            result_status=ResultStatus.SUCCESS,
            protocol=Protocol.MCP,
            action_type=ActionType.TOOL_CALL,
            authorization=Authorization(type=AuthorizationType.AUTH_NONE),
        ))
        self.assertEqual(j['type'], 'ACTION')
        self.assertEqual(j['payload']['tool_name'], 'test_tool')
        self.assertEqual(j['payload']['result_status'], 'SUCCESS')
        self.assertEqual(j['payload']['protocol'], 'MCP')
        self.assertEqual(j['payload']['authorization']['type'], 'AUTH_NONE')

    def test_boot_json(self):
        j = self._write_and_read(BootPayload(agent_name="test-agent"))
        self.assertEqual(j['type'], 'BOOT')
        self.assertEqual(j['payload']['agent_name'], 'test-agent')
        self.assertIn('sdk_name', j['payload'])
        self.assertIn('chain_level', j['payload'])

    def test_gap_json(self):
        j = self._write_and_read(GapPayload(
            first_lost_sequence=5,
            last_lost_sequence=10,
            count=6,
            reason=GapReason.DISK_FULL,
            detail="disk full",
        ))
        self.assertEqual(j['type'], 'GAP')
        self.assertEqual(j['payload']['first_lost_sequence'], 5)
        self.assertEqual(j['payload']['last_lost_sequence'], 10)
        self.assertEqual(j['payload']['count'], 6)
        self.assertEqual(j['payload']['reason'], 'DISK_FULL')
        self.assertEqual(j['payload']['detail'], 'disk full')

    def test_checkpoint_json(self):
        j = self._write_and_read(CheckpointPayload(
            record_count=100,
            gap_count=1,
            chain_hash=b'\xaa' * 32,
            merkle_root=b'\xbb' * 32,
            signature=b'\xcc' * 64,
            signing_key_id=b'\xdd' * 32,
            evidence_available=50,
            evidence_exported=40,
            evidence_expired=5,
            evidence_missing=5,
        ))
        self.assertEqual(j['type'], 'CHECKPOINT')
        self.assertEqual(j['payload']['record_count'], 100)
        self.assertEqual(j['payload']['gap_count'], 1)
        self.assertEqual(j['payload']['chain_hash'], ('aa' * 32))
        self.assertEqual(j['payload']['evidence_available'], 50)
        self.assertNotIn('raw', j['payload'])

    def test_recovery_json(self):
        j = self._write_and_read(RecoveryPayload(
            records_verified=200,
            records_truncated=10,
            last_valid_seq=190,
            recovery_method=RecoveryMethod.CHECKPOINT_FILE,
            detail="restored from checkpoint",
        ))
        self.assertEqual(j['type'], 'RECOVERY')
        self.assertEqual(j['payload']['records_verified'], 200)
        self.assertEqual(j['payload']['records_truncated'], 10)
        self.assertEqual(j['payload']['last_valid_seq'], 190)
        self.assertEqual(j['payload']['recovery_method'], 'CHECKPOINT_FILE')
        self.assertEqual(j['payload']['detail'], 'restored from checkpoint')

    def test_key_json(self):
        j = self._write_and_read(KeyPayload(
            public_key=b'\x11' * 32,
            key_id=b'\x22' * 32,
            expires_at=1720000000000,
            supersedes_key_id=b'\x33' * 32,
        ))
        self.assertEqual(j['type'], 'KEY')
        self.assertEqual(j['payload']['public_key'], '11' * 32)
        self.assertEqual(j['payload']['key_id'], '22' * 32)
        self.assertEqual(j['payload']['expires_at'], 1720000000000)
        self.assertEqual(j['payload']['supersedes_key_id'], '33' * 32)

    def test_witness_json(self):
        j = self._write_and_read(WitnessPayload(
            witness_id="witness-1",
            checkpoint_seq=50,
            checkpoint_hash=b'\xaa' * 32,
            witness_timestamp=1710000005000,
            receipt_signature=b'\xbb' * 64,
            witness_public_key=b'\xcc' * 32,
        ))
        self.assertEqual(j['type'], 'WITNESS')
        self.assertEqual(j['payload']['witness_id'], 'witness-1')
        self.assertEqual(j['payload']['checkpoint_seq'], 50)
        self.assertEqual(j['payload']['witness_timestamp'], 1710000005000)
        self.assertNotIn('raw', j['payload'])


# ===================================================================
# 4. Conformance test vector
# ===================================================================

class TestConformanceVector(unittest.TestCase):
    """Generate a known conformance test vector for cross-implementation testing."""

    def test_action_conformance_vector(self):
        """Fixed ActionRecord with known bytes -> deterministic hash.

        This test uses b'\\x01'*16 etc. for all byte fields so the output is
        identical across every AHP SDK implementation.
        """
        record = Record(
            record_id=b'\x01' * 16,
            agent_id=b'\x02' * 16,
            session_id=b'\x03' * 16,
            timestamp_ms=1710000000000,
            sequence=1,
            prev_hash=ZERO_HASH_32,
            schema_version=SCHEMA_VERSION,
            record_type=RecordType.ACTION,
            payload=ActionPayload(
                parent_action_id=ZERO_UUID,
                tool_name="read_file",
                parameters_hash=b'\xaa' * 16,
                result_hash=b'\xbb' * 16,
                result_status=ResultStatus.SUCCESS,
                response_time_ms=42,
                protocol=Protocol.MCP,
                action_type=ActionType.TOOL_CALL,
                target_entity="",
                evidence_uri="",
                redacted=False,
                model_id="",
                input_token_count=0,
                output_token_count=0,
                authorization=Authorization(
                    type=AuthorizationType.AUTH_NONE,
                    entries=[],
                ),
            ),
        )

        stored = canonical_bytes(record)
        digest = hashlib.sha256(stored).hexdigest()

        # Print for cross-implementation conformance
        print(f"\n=== CONFORMANCE TEST VECTOR ===")
        print(f"Canonical bytes hex ({len(stored)} bytes):")
        print(stored.hex())
        print(f"SHA-256: {digest}")
        print(f"=== END VECTOR ===\n")

        # Determinism: re-serialize must produce identical bytes
        stored2 = canonical_bytes(record)
        self.assertEqual(stored, stored2)
        self.assertEqual(hashlib.sha256(stored2).hexdigest(), digest)

        # Parse back and verify key fields
        env = parse_envelope(stored)
        self.assertEqual(env['record_id'], b'\x01' * 16)
        self.assertEqual(env['agent_id'], b'\x02' * 16)
        self.assertEqual(env['session_id'], b'\x03' * 16)
        self.assertEqual(env['timestamp_ms'], 1710000000000)
        self.assertEqual(env['sequence'], 1)
        self.assertEqual(env['prev_hash'], ZERO_HASH_32)
        self.assertEqual(env['schema_version'], SCHEMA_VERSION)
        self.assertEqual(env['record_type'], RecordType.ACTION)

        parsed = parse_action_payload(env['payload_bytes'])
        self.assertEqual(parsed['tool_name'], "read_file")
        self.assertEqual(parsed['parameters_hash'], b'\xaa' * 16)
        self.assertEqual(parsed['result_hash'], b'\xbb' * 16)
        self.assertEqual(parsed['result_status'], ResultStatus.SUCCESS)
        self.assertEqual(parsed['response_time_ms'], 42)


# ===================================================================
# 5. Envelope round-trip for all types
# ===================================================================

class TestEnvelopeAllTypes(unittest.TestCase):
    """Verify the envelope fields are correctly parsed for every record type."""

    def _assert_envelope(self, record: Record) -> None:
        stored = canonical_bytes(record)
        env = parse_envelope(stored)
        self.assertEqual(env['record_id'], record.record_id)
        self.assertEqual(env['agent_id'], record.agent_id)
        self.assertEqual(env['session_id'], record.session_id)
        self.assertEqual(env['timestamp_ms'], record.timestamp_ms)
        self.assertEqual(env['sequence'], record.sequence)
        self.assertEqual(env['prev_hash'], record.prev_hash)
        self.assertEqual(env['schema_version'], record.schema_version)
        self.assertEqual(env['record_type'], record.record_type)

    def test_action_envelope(self):
        r = _make_record(ActionPayload(authorization=Authorization(type=AuthorizationType.AUTH_NONE)), RecordType.ACTION)
        self._assert_envelope(r)

    def test_boot_envelope(self):
        r = _make_record(BootPayload(), RecordType.BOOT)
        self._assert_envelope(r)

    def test_gap_envelope(self):
        r = _make_record(GapPayload(reason=GapReason.CRASH), RecordType.GAP)
        self._assert_envelope(r)

    def test_checkpoint_envelope(self):
        r = _make_record(CheckpointPayload(), RecordType.CHECKPOINT)
        self._assert_envelope(r)

    def test_recovery_envelope(self):
        r = _make_record(RecoveryPayload(), RecordType.RECOVERY)
        self._assert_envelope(r)

    def test_key_envelope(self):
        r = _make_record(KeyPayload(), RecordType.KEY)
        self._assert_envelope(r)

    def test_witness_envelope(self):
        r = _make_record(WitnessPayload(), RecordType.WITNESS)
        self._assert_envelope(r)


if __name__ == '__main__':
    unittest.main()
