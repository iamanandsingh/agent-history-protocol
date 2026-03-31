"""Integration tests — real interception, multi-agent, evidence, PII, witness.

These tests verify the FULL pipeline, not just individual components.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
import time
import unittest
from http.server import HTTPServer

from ahp.core.chain import (
    ChainReader,
    ChainWriter,
    parse_action_payload,
    parse_envelope,
)
from ahp.core.evidence import EvidenceStore
from ahp.core.filters import FilterPipeline
from ahp.core.json_format import record_to_json
from ahp.core.records import (
    ActionPayload,
    Authorization,
    AuthorizationEntry,
    BootPayload,
)
from ahp.core.signing import compute_merkle_root, generate_keypair, sign, verify_signature
from ahp.core.types import (
    ActionType,
    AuthorizationDecision,
    AuthorizationType,
    AuthorizerType,
    Protocol,
    ResultStatus,
)
from ahp.core.uuid7 import uuid7, uuid7_to_str
from ahp.core.verify import verify_chain
from ahp.interceptors.http_helper import _detect_llm, create_action_from_http
from ahp.interceptors.mcp_helper import create_action_from_mcp


class TestHTTPInterceptor(unittest.TestCase):
    """Test HTTP interceptor with realistic HTTP request/response data."""

    def test_detect_openai_endpoint(self):
        name, provider = _detect_llm("https://api.openai.com/v1/chat/completions")
        self.assertEqual(name, "openai.chat.completions")
        self.assertEqual(provider, "openai")

    def test_detect_anthropic_endpoint(self):
        name, provider = _detect_llm("https://api.anthropic.com/v1/messages")
        self.assertEqual(name, "anthropic.messages")
        self.assertEqual(provider, "anthropic")

    def test_non_llm_endpoint(self):
        name, provider = _detect_llm("https://api.stripe.com/v1/charges")
        self.assertIsNone(name)
        self.assertEqual(provider, "")

    def test_openai_inference_action(self):
        """Simulate a real OpenAI API call and verify the ActionPayload."""
        request_body = json.dumps(
            {
                "model": "gpt-4",
                "messages": [{"role": "user", "content": "Hello"}],
            }
        ).encode()

        response_body = json.dumps(
            {
                "choices": [{"message": {"content": "Hi there!"}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5},
            }
        ).encode()

        action = create_action_from_http(
            method="POST",
            url="https://api.openai.com/v1/chat/completions",
            request_body=request_body,
            response_body=response_body,
            status_code=200,
            duration_ms=850,
        )

        self.assertEqual(action.action_type, ActionType.INFERENCE)
        self.assertEqual(action.tool_name, "openai.chat.completions")
        self.assertEqual(action.model_id, "gpt-4")
        self.assertEqual(action.input_token_count, 10)
        self.assertEqual(action.output_token_count, 5)
        self.assertEqual(action.result_status, ResultStatus.SUCCESS)
        self.assertEqual(action.response_time_ms, 850)
        self.assertEqual(action.protocol, Protocol.HTTP)
        self.assertNotEqual(action.parameters_hash, b"\x00" * 16)
        self.assertNotEqual(action.result_hash, b"\x00" * 16)

    def test_anthropic_inference_action(self):
        """Simulate an Anthropic API call."""
        request_body = json.dumps(
            {
                "model": "claude-sonnet-4-6",
                "messages": [{"role": "user", "content": "Explain AHP"}],
            }
        ).encode()

        response_body = json.dumps(
            {
                "content": [{"text": "AHP is a protocol..."}],
                "usage": {"input_tokens": 15, "output_tokens": 100},
            }
        ).encode()

        action = create_action_from_http(
            method="POST",
            url="https://api.anthropic.com/v1/messages",
            request_body=request_body,
            response_body=response_body,
            status_code=200,
            duration_ms=1200,
        )

        self.assertEqual(action.action_type, ActionType.INFERENCE)
        self.assertEqual(action.tool_name, "anthropic.messages")
        self.assertEqual(action.model_id, "claude-sonnet-4-6")
        self.assertEqual(action.input_token_count, 15)
        self.assertEqual(action.output_token_count, 100)

    def test_regular_http_tool_call(self):
        """Non-LLM HTTP call should be TOOL_CALL."""
        action = create_action_from_http(
            method="POST",
            url="https://api.stripe.com/v1/charges",
            request_body=b'{"amount": 4999}',
            response_body=b'{"id": "ch_123", "status": "succeeded"}',
            status_code=200,
            duration_ms=350,
        )

        self.assertEqual(action.action_type, ActionType.TOOL_CALL)
        self.assertEqual(action.tool_name, "POST https://api.stripe.com/v1/charges")
        self.assertEqual(action.model_id, "")
        self.assertEqual(action.result_status, ResultStatus.SUCCESS)

    def test_http_error_status(self):
        """HTTP 500 should be ERROR."""
        action = create_action_from_http(
            method="GET",
            url="https://api.example.com/data",
            request_body=b"",
            response_body=b"Internal Server Error",
            status_code=500,
            duration_ms=100,
        )

        self.assertEqual(action.result_status, ResultStatus.ERROR)

    def test_http_timeout_status(self):
        """HTTP 408/504 should be TIMEOUT."""
        action = create_action_from_http(
            method="GET",
            url="https://api.example.com/slow",
            request_body=b"",
            response_body=b"Gateway Timeout",
            status_code=504,
            duration_ms=30000,
        )

        self.assertEqual(action.result_status, ResultStatus.TIMEOUT)

    def test_http_with_pii_filter(self):
        """HTTP interceptor with PII filter should redact and hash filtered content."""
        pipeline = FilterPipeline(presets=["credentials"])

        action = create_action_from_http(
            method="POST",
            url="https://api.example.com/data",
            request_body=b"Authorization: Bearer sk-1234567890abcdef1234567890abcdef",
            response_body=b'{"status": "ok"}',
            status_code=200,
            duration_ms=50,
            filter_pipeline=pipeline,
        )

        self.assertTrue(action.redacted)


class TestMCPInterceptor(unittest.TestCase):
    """Test MCP interceptor with realistic MCP tool call data."""

    def test_basic_tool_call(self):
        action = create_action_from_mcp(
            tool_name="read_file",
            parameters={"path": "/etc/hosts"},
            result="127.0.0.1 localhost",
            duration_ms=42,
            target_entity="/etc/hosts",
        )

        self.assertEqual(action.tool_name, "read_file")
        self.assertEqual(action.action_type, ActionType.TOOL_CALL)
        self.assertEqual(action.protocol, Protocol.MCP)
        self.assertEqual(action.result_status, ResultStatus.SUCCESS)
        self.assertEqual(action.response_time_ms, 42)
        self.assertNotEqual(action.parameters_hash, b"\x00" * 16)
        self.assertNotEqual(action.result_hash, b"\x00" * 16)

    def test_failed_tool_call(self):
        action = create_action_from_mcp(
            tool_name="delete_file",
            parameters={"path": "/nonexistent"},
            result={"error": "FileNotFoundError"},
            duration_ms=5,
            success=False,
        )

        self.assertEqual(action.result_status, ResultStatus.ERROR)

    def test_deterministic_hashing(self):
        """Same inputs should produce same hashes."""
        a1 = create_action_from_mcp(
            tool_name="search",
            parameters={"query": "test"},
            result={"results": [1, 2, 3]},
            duration_ms=100,
        )
        a2 = create_action_from_mcp(
            tool_name="search",
            parameters={"query": "test"},
            result={"results": [1, 2, 3]},
            duration_ms=100,
        )
        self.assertEqual(a1.parameters_hash, a2.parameters_hash)
        self.assertEqual(a1.result_hash, a2.result_hash)

    def test_mcp_with_pii_filter(self):
        pipeline = FilterPipeline(presets=["pci"])

        action = create_action_from_mcp(
            tool_name="process_payment",
            parameters={"card": "4111 1111 1111 1111", "amount": 49.99},
            result={"status": "charged"},
            duration_ms=200,
            filter_pipeline=pipeline,
        )

        self.assertTrue(action.redacted)


class TestEvidenceStore(unittest.TestCase):
    """Test evidence store — content-addressed storage."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.store = EvidenceStore(os.path.join(self.tmpdir, "evidence"))

    def test_store_and_retrieve(self):
        payload = b'{"path": "/etc/hosts"}'
        hash_16 = self.store.store(payload)

        self.assertEqual(len(hash_16), 16)
        retrieved = self.store.retrieve(hash_16)
        self.assertEqual(retrieved, payload)

    def test_verify(self):
        payload = b"test payload"
        hash_16 = self.store.store(payload)
        self.assertTrue(self.store.verify(hash_16))

    def test_missing_evidence(self):
        self.assertIsNone(self.store.retrieve(b"\x99" * 16))
        self.assertFalse(self.store.verify(b"\x99" * 16))

    def test_content_addressed(self):
        """Same content should produce same hash and not duplicate."""
        h1 = self.store.store(b"same content")
        h2 = self.store.store(b"same content")
        self.assertEqual(h1, h2)
        self.assertEqual(self.store.count()["available"], 1)

    def test_different_content_different_hash(self):
        h1 = self.store.store(b"content A")
        h2 = self.store.store(b"content B")
        self.assertNotEqual(h1, h2)


class TestPIIFilters(unittest.TestCase):
    """Test PII filter pipeline with real PII data."""

    def test_credit_card_redaction(self):
        pipeline = FilterPipeline(presets=["pci"])
        filtered, redacted = pipeline.apply(b"Card: 4111 1111 1111 1111", scope="parameters")
        self.assertTrue(redacted)
        self.assertIn(b"[REDACTED:CC]", filtered)
        self.assertNotIn(b"4111", filtered)

    def test_ssn_redaction(self):
        pipeline = FilterPipeline(presets=["pii-us"])
        filtered, redacted = pipeline.apply(b"SSN: 123-45-6789", scope="parameters")
        self.assertTrue(redacted)
        self.assertIn(b"[REDACTED:SSN]", filtered)

    def test_bearer_token_redaction(self):
        pipeline = FilterPipeline(presets=["credentials"])
        filtered, redacted = pipeline.apply(b"Authorization: Bearer sk-1234567890abcdef", scope="parameters")
        self.assertTrue(redacted)
        self.assertIn(b"[REDACTED:TOKEN]", filtered)

    def test_no_match_no_redaction(self):
        pipeline = FilterPipeline(presets=["pci"])
        filtered, redacted = pipeline.apply(b"Hello world, no PII here", scope="parameters")
        self.assertFalse(redacted)
        self.assertEqual(filtered, b"Hello world, no PII here")

    def test_binary_payload_skipped(self):
        pipeline = FilterPipeline(presets=["pci"])
        binary = bytes(range(256))  # non-UTF8 bytes
        filtered, redacted = pipeline.apply(binary, scope="parameters")
        self.assertFalse(redacted)
        self.assertEqual(filtered, binary)

    def test_hash_changes_with_filter(self):
        """Filtered content should produce different hash than original."""
        pipeline = FilterPipeline(presets=["pci"])
        payload = b"Card: 4111 1111 1111 1111"

        hash_no_filter = hashlib.sha256(payload).digest()[:16]
        hash_filtered, _, _ = pipeline.hash_payload(payload, "parameters")

        self.assertNotEqual(hash_no_filter, hash_filtered)

    def test_config_hash_deterministic(self):
        p1 = FilterPipeline(presets=["pci", "credentials"])
        p2 = FilterPipeline(presets=["pci", "credentials"])
        self.assertEqual(p1.config_hash(), p2.config_hash())

    def test_config_hash_changes_with_different_filters(self):
        p1 = FilterPipeline(presets=["pci"])
        p2 = FilterPipeline(presets=["credentials"])
        self.assertNotEqual(p1.config_hash(), p2.config_hash())


class TestSigning(unittest.TestCase):
    """Test Ed25519 signing and Merkle root computation."""

    def test_generate_keypair(self):
        kp = generate_keypair()
        self.assertEqual(len(kp.public_key_bytes), 32)
        self.assertEqual(len(kp.private_key_bytes), 32)
        self.assertEqual(len(kp.key_id), 32)
        self.assertEqual(kp.key_id, hashlib.sha256(kp.public_key_bytes).digest())

    def test_sign_and_verify(self):
        kp = generate_keypair()
        message = b"test message for signing"
        sig = sign(message, kp.private_key_bytes)

        if sig == b"\x00" * 64:
            self.skipTest("cryptography library not installed")

        self.assertEqual(len(sig), 64)
        self.assertTrue(verify_signature(message, sig, kp.public_key_bytes))

    def test_wrong_key_fails(self):
        kp1 = generate_keypair()
        kp2 = generate_keypair()
        message = b"test"
        sig = sign(message, kp1.private_key_bytes)

        if sig == b"\x00" * 64:
            self.skipTest("cryptography library not installed")

        self.assertFalse(verify_signature(message, sig, kp2.public_key_bytes))

    def test_tampered_message_fails(self):
        kp = generate_keypair()
        sig = sign(b"original", kp.private_key_bytes)

        if sig == b"\x00" * 64:
            self.skipTest("cryptography library not installed")

        self.assertFalse(verify_signature(b"tampered", sig, kp.public_key_bytes))

    def test_merkle_root_single(self):
        h = hashlib.sha256(b"test").digest()
        root = compute_merkle_root([h])
        # RFC 6962 leaf prefix: root of single element is SHA256(0x00 + h)
        expected = hashlib.sha256(b"\x00" + h).digest()
        self.assertEqual(root, expected)

    def test_merkle_root_multiple(self):
        hashes = [hashlib.sha256(f"record{i}".encode()).digest() for i in range(5)]
        root = compute_merkle_root(hashes)
        self.assertEqual(len(root), 32)
        # Same input should produce same root
        root2 = compute_merkle_root(hashes)
        self.assertEqual(root, root2)

    def test_merkle_root_order_matters(self):
        h1 = hashlib.sha256(b"a").digest()
        h2 = hashlib.sha256(b"b").digest()
        r1 = compute_merkle_root([h1, h2])
        r2 = compute_merkle_root([h2, h1])
        self.assertNotEqual(r1, r2)


class TestMultiAgent(unittest.TestCase):
    """Test multi-agent authorization with cross-chain verification."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def test_two_agents_cross_chain_authorization(self):
        """Agent A requests approval from Agent B. Both chains record the event."""
        chain_a = os.path.join(self.tmpdir, "agent_a.ahp")
        chain_b = os.path.join(self.tmpdir, "agent_b.ahp")

        agent_a_id = uuid7()
        agent_b_id = uuid7()
        session_id = uuid7()

        writer_a = ChainWriter(chain_a, agent_id=agent_a_id, session_id=session_id)
        writer_b = ChainWriter(chain_b, agent_id=agent_b_id, session_id=session_id)

        # Agent B approves Agent A's request (Agent B's chain)
        approval_record = writer_b.write_record(
            ActionPayload(
                tool_name="authorization_decision",
                parameters_hash=hashlib.sha256(b"delete_account request").digest()[:16],
                result_hash=hashlib.sha256(b"APPROVED").digest()[:16],
                result_status=ResultStatus.SUCCESS,
                response_time_ms=50,
                protocol=Protocol.A2A,
                action_type=ActionType.MESSAGE,
                target_entity=f"agent:{uuid7_to_str(agent_a_id)}",
                authorization=Authorization(type=AuthorizationType.AUTH_NONE),
            )
        )

        # Agent A executes with Agent B's authorization (Agent A's chain)
        writer_a.write_record(
            ActionPayload(
                tool_name="delete_account",
                parameters_hash=hashlib.sha256(b'{"user_id": 103}').digest()[:16],
                result_hash=hashlib.sha256(b'{"status": "deleted"}').digest()[:16],
                result_status=ResultStatus.SUCCESS,
                response_time_ms=200,
                protocol=Protocol.MCP,
                action_type=ActionType.TOOL_CALL,
                target_entity="user:103",
                authorization=Authorization(
                    type=AuthorizationType.AUTH_AGENT,
                    entries=[
                        AuthorizationEntry(
                            authorizer_type=AuthorizerType.AUTHORIZER_AGENT,
                            authorizer_id="supervisor-bot",
                            authorizer_agent_id=agent_b_id,
                            authorizer_seq=approval_record.sequence,
                            decision=AuthorizationDecision.APPROVED,
                            timestamp_ms=int(time.time() * 1000),
                        )
                    ],
                ),
            )
        )

        # Verify both chains are valid
        result_a = verify_chain(chain_a)
        result_b = verify_chain(chain_b)
        self.assertTrue(result_a.valid)
        self.assertTrue(result_b.valid)

        # Cross-chain verification: Agent A's authorization entry
        # references Agent B's sequence number
        reader_a = ChainReader(chain_a)
        records_a = reader_a.read_all()
        env_a = parse_envelope(records_a[0])
        payload_a = parse_action_payload(env_a["payload_bytes"])

        auth_entry = payload_a["authorization"]["entries"][0]
        self.assertEqual(auth_entry["authorizer_agent_id"], agent_b_id)
        self.assertEqual(auth_entry["authorizer_seq"], approval_record.sequence)

        # Verify the referenced record exists in Agent B's chain
        reader_b = ChainReader(chain_b)
        records_b = reader_b.read_all()
        env_b = parse_envelope(records_b[0])
        self.assertEqual(env_b["sequence"], auth_entry["authorizer_seq"])

    def test_rejected_authorization(self):
        """Agent tries action, gets rejected. Recorded with ERROR status."""
        chain_path = os.path.join(self.tmpdir, "rejected.ahp")
        writer = ChainWriter(chain_path)

        writer.write_record(
            ActionPayload(
                tool_name="delete_database",
                parameters_hash=hashlib.sha256(b'{"db": "production"}').digest()[:16],
                result_hash=b"\x00" * 16,  # no result — action never executed
                result_status=ResultStatus.ERROR,
                response_time_ms=0,
                protocol=Protocol.MCP,
                action_type=ActionType.TOOL_CALL,
                authorization=Authorization(
                    type=AuthorizationType.AUTH_POLICY,
                    entries=[
                        AuthorizationEntry(
                            authorizer_type=AuthorizerType.AUTHORIZER_POLICY_ENGINE,
                            authorizer_id="openshell:production-safety",
                            decision=AuthorizationDecision.REJECTED,
                            timestamp_ms=int(time.time() * 1000),
                        )
                    ],
                ),
            )
        )

        # Chain is valid even with rejected actions
        result = verify_chain(chain_path)
        self.assertTrue(result.valid)

        # Verify the rejection is recorded
        reader = ChainReader(chain_path)
        records = reader.read_all()
        env = parse_envelope(records[0])
        payload = parse_action_payload(env["payload_bytes"])

        self.assertEqual(payload["result_status"], ResultStatus.ERROR.value)
        self.assertEqual(payload["result_hash"], b"\x00" * 16)
        self.assertEqual(
            payload["authorization"]["entries"][0]["decision"],
            AuthorizationDecision.REJECTED.value,
        )

    def test_multi_party_authorization(self):
        """Action requires both agent AND human approval."""
        chain_path = os.path.join(self.tmpdir, "multi_party.ahp")
        supervisor_id = uuid7()
        writer = ChainWriter(chain_path)

        writer.write_record(
            ActionPayload(
                tool_name="transfer_funds",
                parameters_hash=hashlib.sha256(b'{"amount": 50000}').digest()[:16],
                result_hash=hashlib.sha256(b'{"tx_id": "TX-001"}').digest()[:16],
                result_status=ResultStatus.SUCCESS,
                response_time_ms=500,
                protocol=Protocol.HTTP,
                action_type=ActionType.TOOL_CALL,
                authorization=Authorization(
                    type=AuthorizationType.AUTH_MULTI_PARTY,
                    entries=[
                        AuthorizationEntry(
                            authorizer_type=AuthorizerType.AUTHORIZER_AGENT,
                            authorizer_id="compliance-bot",
                            authorizer_agent_id=supervisor_id,
                            authorizer_seq=100,
                            decision=AuthorizationDecision.APPROVED,
                            timestamp_ms=int(time.time() * 1000) - 2000,
                        ),
                        AuthorizationEntry(
                            authorizer_type=AuthorizerType.AUTHORIZER_HUMAN,
                            authorizer_id="user:cfo@company.com",
                            decision=AuthorizationDecision.APPROVED,
                            timestamp_ms=int(time.time() * 1000),
                        ),
                    ],
                ),
            )
        )

        result = verify_chain(chain_path)
        self.assertTrue(result.valid)

        reader = ChainReader(chain_path)
        records = reader.read_all()
        j = record_to_json(records[0])

        self.assertEqual(j["payload"]["authorization"]["type"], "AUTH_MULTI_PARTY")
        self.assertEqual(len(j["payload"]["authorization"]["entries"]), 2)
        self.assertEqual(j["payload"]["authorization"]["entries"][0]["authorizer_type"], "AUTHORIZER_AGENT")
        self.assertEqual(j["payload"]["authorization"]["entries"][1]["authorizer_type"], "AUTHORIZER_HUMAN")


class TestEndToEndFlow(unittest.TestCase):
    """Full pipeline: interceptor → filter → evidence → chain → verify → JSON."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def test_full_pipeline(self):
        """Simulate a real agent flow with interceptors, filters, and evidence."""
        chain_path = os.path.join(self.tmpdir, "e2e.ahp")
        evidence_path = os.path.join(self.tmpdir, "evidence")

        writer = ChainWriter(chain_path)
        store = EvidenceStore(evidence_path)
        pipeline = FilterPipeline(presets=["pci", "credentials"])

        # 1. Boot record
        writer.write_record(
            BootPayload(
                agent_name="e2e-test-bot",
                interceptors=["http", "mcp"],
                inference_recording=True,
                authorization_recording=True,
                filter_config_hash=pipeline.config_hash(),
            )
        )

        # 2. Simulate LLM inference via HTTP interceptor
        request_body = json.dumps(
            {
                "model": "claude-sonnet-4-6",
                "messages": [{"role": "user", "content": "Process payment"}],
            }
        ).encode()
        response_body = json.dumps(
            {
                "content": [{"text": "I'll process the payment now."}],
                "usage": {"input_tokens": 20, "output_tokens": 30},
            }
        ).encode()

        inference_action = create_action_from_http(
            method="POST",
            url="https://api.anthropic.com/v1/messages",
            request_body=request_body,
            response_body=response_body,
            status_code=200,
            duration_ms=950,
            filter_pipeline=pipeline,
        )
        inference_record = writer.write_record(inference_action)

        # Store evidence
        store.store(request_body)
        store.store(response_body)

        # 3. Simulate MCP tool call with PII
        mcp_action = create_action_from_mcp(
            tool_name="charge_card",
            parameters={"card": "4111 1111 1111 1111", "amount": 99.99},
            result={"status": "charged", "tx_id": "TX-456"},
            duration_ms=350,
            target_entity="payment_api",
            filter_pipeline=pipeline,
        )
        # Set parent to inference and add human authorization
        mcp_action.parent_action_id = inference_record.record_id
        mcp_action.authorization = Authorization(
            type=AuthorizationType.AUTH_HUMAN,
            entries=[
                AuthorizationEntry(
                    authorizer_type=AuthorizerType.AUTHORIZER_HUMAN,
                    authorizer_id="user:operator",
                    decision=AuthorizationDecision.APPROVED,
                    timestamp_ms=int(time.time() * 1000),
                )
            ],
        )
        writer.write_record(mcp_action)

        # 4. Verify the chain
        result = verify_chain(chain_path)
        self.assertTrue(result.valid, f"Chain invalid: {result.error}")
        self.assertEqual(result.records_checked, 3)

        # 5. Read back and verify JSON
        reader = ChainReader(chain_path)
        records = reader.read_all()
        self.assertEqual(len(records), 3)

        # Boot record
        j0 = record_to_json(records[0])
        self.assertEqual(j0["type"], "BOOT")
        self.assertEqual(j0["payload"]["agent_name"], "e2e-test-bot")
        self.assertTrue(j0["payload"]["authorization_recording"])

        # Inference record
        j1 = record_to_json(records[1])
        self.assertEqual(j1["payload"]["action_type"], "INFERENCE")
        self.assertEqual(j1["payload"]["model_id"], "claude-sonnet-4-6")
        self.assertEqual(j1["payload"]["input_token_count"], 20)
        self.assertEqual(j1["payload"]["output_token_count"], 30)

        # Tool call with authorization
        j2 = record_to_json(records[2])
        self.assertEqual(j2["payload"]["tool_name"], "charge_card")
        self.assertTrue(j2["payload"]["redacted"])  # PII filter caught CC
        self.assertEqual(j2["payload"]["authorization"]["type"], "AUTH_HUMAN")
        self.assertEqual(j2["payload"]["authorization"]["entries"][0]["decision"], "APPROVED")
        # Parent links to inference
        self.assertIsNotNone(j2["payload"]["parent_action_id"])

        # 6. Evidence store has the files
        self.assertEqual(store.count()["available"], 2)


class TestWitnessServerClient(unittest.TestCase):
    """Test witness server and client together."""

    def test_witness_round_trip(self):
        """Start witness server, send checkpoint, get receipt."""

        from witness.server import WITNESS_ID, WitnessHandler

        # Start server on random port
        server = HTTPServer(("localhost", 0), WitnessHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            endpoint = f"http://localhost:{port}"

            # Send signed checkpoint (witness rejects unsigned)
            import json

            from ahp.core.signing import generate_keypair, sign
            from ahp.core.witness_client import get_identity, send_checkpoint

            kp = generate_keypair()
            agent_id = "test-agent-id"
            chain_hash = "ab" * 32
            sequence = 100
            timestamp_ms = int(time.time() * 1000)

            sign_data = json.dumps(
                {
                    "agent_id": agent_id,
                    "chain_hash": chain_hash,
                    "sequence": sequence,
                    "timestamp_ms": timestamp_ms,
                },
                sort_keys=True,
            ).encode()
            sig_hex = sign(sign_data, kp.private_key_bytes).hex()

            receipt = send_checkpoint(
                endpoint=endpoint,
                agent_id=agent_id,
                chain_hash=chain_hash,
                sequence=sequence,
                timestamp_ms=timestamp_ms,
                signature=sig_hex,
                signing_key_id=kp.key_id.hex(),
                public_key=kp.public_key_bytes.hex(),
            )

            self.assertIsNotNone(receipt, "Witness returned no receipt")
            self.assertEqual(receipt["witness_id"], WITNESS_ID)
            self.assertEqual(receipt["sequence"], 100)
            self.assertIn("witness_timestamp", receipt)
            self.assertIn("witness_signature", receipt)

            # Get identity
            identity = get_identity(endpoint)
            self.assertIsNotNone(identity)
            self.assertEqual(identity["witness_id"], WITNESS_ID)

        finally:
            server.shutdown()


if __name__ == "__main__":
    unittest.main()
