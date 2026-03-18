"""Tests for AHPRecorder -- the main SDK entry point."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from typing import Optional

from ahp.recorder import AHPRecorder
from ahp.config import AHPConfig, FilterConfig, WitnessConfig
from ahp.core.chain import ChainReader, parse_envelope, parse_action_payload, parse_boot_payload, parse_checkpoint_payload, parse_key_payload
from ahp.core.filters import Filter
from ahp.core.records import Authorization, ActionPayload
from ahp.core.types import (
    RecordType, ResultStatus, Protocol, ActionType,
    AuthorizationType, ChainLevel, GapReason,
    ZERO_HASH_32,
)
from ahp.core.signing import HAS_CRYPTO
from ahp.core.verify import verify_chain


def _tmpdir():
    """Create a temporary directory for test chain files."""
    return tempfile.mkdtemp(prefix="ahp_test_")


class TestBasicRecording(unittest.TestCase):
    """test_basic_recording: create recorder, record 3 actions, verify chain valid."""

    def setUp(self):
        self.tmpdir = _tmpdir()
        self.chain_path = os.path.join(self.tmpdir, "basic.ahp")

    def test_basic_recording(self):
        recorder = AHPRecorder(
            agent_name="test-agent",
            chain_path=self.chain_path,
            level=1,
            checkpoint_interval=9999,  # no auto-checkpoint during this test
        )

        # Record 3 actions
        for i in range(3):
            rec = recorder.record_action(
                tool_name="tool_%d" % i,
                parameters=b'{"q": "hello"}',
                result=b'{"answer": "world"}',
                protocol=Protocol.MCP,
                action_type=ActionType.TOOL_CALL,
            )
            self.assertIsNotNone(rec)
            self.assertEqual(rec.record_type, RecordType.ACTION)

        # Verify chain integrity
        result = verify_chain(self.chain_path)
        self.assertTrue(result.valid, "Chain invalid: %s" % getattr(result, 'error', ''))

        # Boot record + 3 action records = 4 total
        reader = ChainReader(self.chain_path)
        records = reader.read_all()
        self.assertEqual(len(records), 4)

        # First record is BOOT
        env0 = parse_envelope(records[0])
        self.assertEqual(env0['record_type'], RecordType.BOOT)

        # Remaining 3 are ACTION
        for i in range(1, 4):
            env = parse_envelope(records[i])
            self.assertEqual(env['record_type'], RecordType.ACTION)


class TestPIIFiltering(unittest.TestCase):
    """test_pii_filtering: record with credit card in params, verify redacted=True."""

    def setUp(self):
        self.tmpdir = _tmpdir()
        self.chain_path = os.path.join(self.tmpdir, "pii.ahp")

    def test_pii_filtering(self):
        recorder = AHPRecorder(
            agent_name="pii-agent",
            chain_path=self.chain_path,
            level=1,
            filter_presets=["pci"],
            checkpoint_interval=9999,
        )

        # Parameters contain a credit card number
        rec = recorder.record_action(
            tool_name="payment",
            parameters=b'{"card": "4111-1111-1111-1111"}',
            result=b'{"status": "ok"}',
            protocol=Protocol.HTTP,
            action_type=ActionType.TOOL_CALL,
        )

        self.assertIsNotNone(rec)

        # Parse the stored action payload and verify redacted flag
        reader = ChainReader(self.chain_path)
        records = reader.read_all()

        # Find the ACTION record (skip BOOT)
        action_bytes = None
        for stored in records:
            env = parse_envelope(stored)
            if env['record_type'] == RecordType.ACTION:
                action_bytes = stored
                break

        self.assertIsNotNone(action_bytes, "No ACTION record found in chain")
        env = parse_envelope(action_bytes)
        action_data = parse_action_payload(env['payload_bytes'])
        self.assertTrue(action_data['redacted'], "Expected redacted=True for CC data")


class TestEvidenceStored(unittest.TestCase):
    """test_evidence_stored: record with evidence=True, verify evidence files created."""

    def setUp(self):
        self.tmpdir = _tmpdir()
        self.chain_path = os.path.join(self.tmpdir, "evidence.ahp")
        self.evidence_path = os.path.join(self.tmpdir, "evidence")

    def test_evidence_stored(self):
        cfg = AHPConfig(
            level=1,
            agent_name="evidence-agent",
            evidence_record=True,
            checkpoint_interval=9999,
        )
        recorder = AHPRecorder(
            agent_name="evidence-agent",
            chain_path=self.chain_path,
            evidence_path=self.evidence_path,
            config=cfg,
        )

        self.assertIsNotNone(recorder.evidence_store)

        rec = recorder.record_action(
            tool_name="search",
            parameters=b'{"query": "return policy"}',
            result=b'{"matches": ["policy1", "policy2"]}',
            protocol=Protocol.MCP,
            action_type=ActionType.TOOL_CALL,
        )

        # Evidence directory should have files
        evidence_files = list(os.listdir(self.evidence_path))
        self.assertGreater(len(evidence_files), 0, "No evidence files created")

        # Each evidence file should be retrievable by its hash
        for fname in evidence_files:
            hash_16 = bytes.fromhex(fname)
            self.assertTrue(
                recorder.evidence_store.verify(hash_16),
                "Evidence file %s failed verification" % fname,
            )


class TestAutoCheckpoint(unittest.TestCase):
    """test_auto_checkpoint: set checkpoint_interval=5, record 6 actions, verify checkpoint emitted."""

    def setUp(self):
        self.tmpdir = _tmpdir()
        self.chain_path = os.path.join(self.tmpdir, "checkpoint.ahp")

    def test_auto_checkpoint(self):
        recorder = AHPRecorder(
            agent_name="ckpt-agent",
            chain_path=self.chain_path,
            level=1,
            checkpoint_interval=5,
        )

        # The boot record is record #1, so after 4 more actions the checkpoint
        # counter (which starts at 1 from the boot) will reach 5.
        for i in range(6):
            recorder.record_action(
                tool_name="tool_%d" % i,
                parameters=b"{}",
                result=b"{}",
                protocol=Protocol.MCP,
                action_type=ActionType.TOOL_CALL,
            )

        # Read chain and look for CHECKPOINT records
        reader = ChainReader(self.chain_path)
        records = reader.read_all()

        checkpoint_count = 0
        for stored in records:
            env = parse_envelope(stored)
            if env['record_type'] == RecordType.CHECKPOINT:
                checkpoint_count += 1

        self.assertGreaterEqual(
            checkpoint_count, 1,
            "Expected at least 1 checkpoint record, found %d" % checkpoint_count,
        )


class TestFailOpen(unittest.TestCase):
    """test_fail_open: recorder.safe_record with broken data, verify agent doesn't crash, GapRecord emitted."""

    def setUp(self):
        self.tmpdir = _tmpdir()
        self.chain_path = os.path.join(self.tmpdir, "failopen.ahp")

    def test_fail_open(self):
        recorder = AHPRecorder(
            agent_name="failopen-agent",
            chain_path=self.chain_path,
            level=1,
            checkpoint_interval=9999,
        )

        # Monkey-patch the chain writer to force an error on the next write
        original_write = recorder._chain.write_record

        call_count = [0]

        def failing_write(payload, **kwargs):
            call_count[0] += 1
            # Fail on the first call after setup (which is a record_action call)
            if call_count[0] == 1:
                raise IOError("Simulated disk failure")
            return original_write(payload, **kwargs)

        recorder._chain.write_record = failing_write

        # This should NOT raise -- fail-open
        result = recorder.safe_record(
            tool_name="broken_tool",
            parameters=b"{}",
            result=b"{}",
            protocol=Protocol.MCP,
            action_type=ActionType.TOOL_CALL,
        )
        self.assertIsNone(result, "safe_record should return None on failure")

        # Restore normal writes
        recorder._chain.write_record = original_write

        # Next successful write should emit a GapRecord first
        rec = recorder.record_action(
            tool_name="recovered_tool",
            parameters=b"{}",
            result=b"{}",
            protocol=Protocol.MCP,
            action_type=ActionType.TOOL_CALL,
        )
        self.assertIsNotNone(rec)

        # Verify chain contains a GAP record
        reader = ChainReader(self.chain_path)
        records = reader.read_all()

        gap_found = False
        for stored in records:
            env = parse_envelope(stored)
            if env['record_type'] == RecordType.GAP:
                gap_found = True
                break

        self.assertTrue(gap_found, "Expected a GAP record after safe_record failure")


class TestBootRecord(unittest.TestCase):
    """test_boot_record: verify first record is BootRecord with correct policy."""

    def setUp(self):
        self.tmpdir = _tmpdir()
        self.chain_path = os.path.join(self.tmpdir, "boot.ahp")

    def test_boot_record(self):
        recorder = AHPRecorder(
            agent_name="boot-agent",
            chain_path=self.chain_path,
            level=2,
            agent_framework="langchain",
            checkpoint_interval=9999,
        )

        reader = ChainReader(self.chain_path)
        records = reader.read_all()

        # First record must be BOOT
        self.assertGreater(len(records), 0, "No records in chain")
        env = parse_envelope(records[0])
        self.assertEqual(env['record_type'], RecordType.BOOT)
        self.assertEqual(env['sequence'], 1)

        # Parse boot payload and verify fields
        boot_data = parse_boot_payload(env['payload_bytes'])
        self.assertEqual(boot_data['agent_name'], "boot-agent")
        self.assertEqual(boot_data['sdk_name'], "ahp-python")
        self.assertEqual(boot_data['chain_level'], ChainLevel.LEVEL_2)
        self.assertEqual(boot_data['agent_framework'], "langchain")
        self.assertIn("python", boot_data['runtime'].lower())


class TestFromConfig(unittest.TestCase):
    """test_from_config: create recorder from config dict, verify settings applied."""

    def setUp(self):
        self.tmpdir = _tmpdir()
        self.chain_path = os.path.join(self.tmpdir, "fromconfig.ahp")

    def test_from_config(self):
        cfg = AHPConfig(
            level=2,
            agent_name="config-agent",
            agent_framework="autogen",
            evidence_record=True,
            inference_record=True,
            checkpoint_interval=100,
            filter_presets=["pci", "credentials"],
            config_source="test",
        )
        recorder = AHPRecorder(
            agent_name="config-agent",
            chain_path=self.chain_path,
            config=cfg,
        )

        # Verify settings were applied
        self.assertEqual(recorder.level, 2)
        self.assertIsNotNone(recorder.keypair, "Level 2 should have a keypair")
        self.assertIsNotNone(recorder.evidence_store, "evidence_record=True should create store")
        self.assertEqual(recorder._checkpoint_interval, 100)

        # Filters should include PCI + credentials presets
        self.assertGreater(
            len(recorder.filter_pipeline.filters), 0,
            "Expected filters from presets",
        )


class TestSigningLevel2(unittest.TestCase):
    """test_signing_level2: create level=2 recorder, verify KeyGenesisRecord and signed checkpoint."""

    def setUp(self):
        self.tmpdir = _tmpdir()
        self.chain_path = os.path.join(self.tmpdir, "signing.ahp")

    def test_signing_level2(self):
        recorder = AHPRecorder(
            agent_name="signing-agent",
            chain_path=self.chain_path,
            level=2,
            checkpoint_interval=9999,
        )

        # Level 2 should have generated a keypair
        self.assertIsNotNone(recorder.keypair)
        self.assertEqual(len(recorder.keypair.public_key_bytes), 32)
        self.assertEqual(len(recorder.keypair.key_id), 32)

        # Chain should have BOOT + KEY records
        reader = ChainReader(self.chain_path)
        records = reader.read_all()
        self.assertGreaterEqual(len(records), 2)

        # Second record should be KEY (KeyGenesis)
        env1 = parse_envelope(records[1])
        self.assertEqual(env1['record_type'], RecordType.KEY)

        # Parse key payload
        key_data = parse_key_payload(env1['payload_bytes'])
        self.assertEqual(key_data['public_key'], recorder.keypair.public_key_bytes)
        self.assertEqual(key_data['key_id'], recorder.keypair.key_id)

        # Record a few actions then emit checkpoint
        for i in range(3):
            recorder.record_action(
                tool_name="tool_%d" % i,
                parameters=b"{}",
                result=b"{}",
                protocol=Protocol.MCP,
                action_type=ActionType.TOOL_CALL,
            )

        cp_rec = recorder.emit_checkpoint()
        self.assertEqual(cp_rec.record_type, RecordType.CHECKPOINT)

        # Parse checkpoint and verify signature is not all zeros
        reader2 = ChainReader(self.chain_path)
        all_records = reader2.read_all()

        cp_bytes = None
        for stored in all_records:
            env = parse_envelope(stored)
            if env['record_type'] == RecordType.CHECKPOINT:
                cp_bytes = stored
                break

        self.assertIsNotNone(cp_bytes, "No CHECKPOINT record found")
        cp_env = parse_envelope(cp_bytes)
        cp_data = parse_checkpoint_payload(cp_env['payload_bytes'])

        # When cryptography is installed, signature should not be all zeros.
        # Without the library, sign() returns a 64-byte zero stub.
        if HAS_CRYPTO:
            self.assertNotEqual(cp_data['signature'], b'\x00' * 64)
        else:
            # Stub signature -- still 64 bytes
            self.assertEqual(len(cp_data['signature']), 64)
        # Merkle root should not be all zeros (we had records)
        self.assertNotEqual(cp_data['merkle_root'], ZERO_HASH_32)
        # Signing key ID should match our keypair
        self.assertEqual(cp_data['signing_key_id'], recorder.keypair.key_id)


class TestInferenceRecording(unittest.TestCase):
    """test_inference_recording: record_inference with model_id and tokens, verify in chain."""

    def setUp(self):
        self.tmpdir = _tmpdir()
        self.chain_path = os.path.join(self.tmpdir, "inference.ahp")

    def test_inference_recording(self):
        recorder = AHPRecorder(
            agent_name="inference-agent",
            chain_path=self.chain_path,
            level=1,
            checkpoint_interval=9999,
        )

        rec = recorder.record_inference(
            tool_name="llm_call",
            parameters=b'{"prompt": "What is 2+2?"}',
            result=b'{"response": "4"}',
            model_id="gpt-4-turbo",
            input_token_count=15,
            output_token_count=3,
            protocol=Protocol.HTTP,
            response_time_ms=450,
        )

        self.assertIsNotNone(rec)
        self.assertEqual(rec.record_type, RecordType.ACTION)

        # Parse the action payload
        reader = ChainReader(self.chain_path)
        records = reader.read_all()

        action_bytes = None
        for stored in records:
            env = parse_envelope(stored)
            if env['record_type'] == RecordType.ACTION:
                action_bytes = stored
                break

        self.assertIsNotNone(action_bytes)
        env = parse_envelope(action_bytes)
        action_data = parse_action_payload(env['payload_bytes'])

        self.assertEqual(action_data['action_type'], ActionType.INFERENCE)
        self.assertEqual(action_data['model_id'], "gpt-4-turbo")
        self.assertEqual(action_data['input_token_count'], 15)
        self.assertEqual(action_data['output_token_count'], 3)
        self.assertEqual(action_data['response_time_ms'], 450)


class TestChainIntegrityAcrossOperations(unittest.TestCase):
    """Verify the chain stays valid across mixed operations."""

    def setUp(self):
        self.tmpdir = _tmpdir()
        self.chain_path = os.path.join(self.tmpdir, "mixed.ahp")

    def test_mixed_operations(self):
        recorder = AHPRecorder(
            agent_name="mixed-agent",
            chain_path=self.chain_path,
            level=2,
            checkpoint_interval=3,
            filter_presets=["pci"],
        )

        # Record some actions (one with PII)
        recorder.record_action(
            tool_name="tool_a",
            parameters=b'{"data": "clean"}',
            result=b'{"ok": true}',
            protocol=Protocol.MCP,
            action_type=ActionType.TOOL_CALL,
        )
        recorder.record_inference(
            tool_name="llm",
            parameters=b'{"prompt": "hi"}',
            result=b'{"text": "hello"}',
            model_id="claude-3",
            input_token_count=5,
            output_token_count=3,
        )
        recorder.record_action(
            tool_name="payment",
            parameters=b'{"card": "4111-1111-1111-1111"}',
            result=b'{}',
            protocol=Protocol.HTTP,
            action_type=ActionType.TOOL_CALL,
        )

        # Manually emit checkpoint
        recorder.emit_checkpoint()

        # Record more
        recorder.record_action(
            tool_name="tool_b",
            parameters=b"{}",
            result=b"{}",
            protocol=Protocol.MCP,
            action_type=ActionType.TOOL_CALL,
        )

        # Chain should still verify
        result = verify_chain(self.chain_path)
        self.assertTrue(result.valid, "Chain invalid: %s" % getattr(result, 'error', ''))


if __name__ == '__main__':
    unittest.main()
