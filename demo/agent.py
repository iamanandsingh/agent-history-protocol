"""Simulated customer support agent — creates realistic AHP records.

This demo creates a chain showing:
1. Agent startup (BootRecord)
2. Simple query (INFERENCE → TOOL_CALL, AUTH_NONE)
3. Refund processing (INFERENCE → TOOL_CALL with AUTH_HUMAN)
4. Blocked action (INFERENCE → TOOL_CALL with AUTH_POLICY, REJECTED)
5. Account deletion (INFERENCE → TOOL_CALL with AUTH_MULTI_PARTY)
"""

import hashlib
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from ahp.core.types import (
    ResultStatus, Protocol, ActionType, AuthorizationType,
    AuthorizerType, AuthorizationDecision, ChainLevel, FsyncMode,
    ZERO_UUID,
)
from ahp.core.records import (
    ActionPayload, BootPayload, Authorization, AuthorizationEntry,
)
from ahp.core.chain import ChainWriter
from ahp.core.uuid7 import uuid7


CHAIN_FILE = "support-bot.ahp"


def _hash16(data: str) -> bytes:
    """SHA-256 truncated to 128 bits (16 bytes) — per spec."""
    return hashlib.sha256(data.encode()).digest()[:16]


def main():
    # Clean up previous run
    Path(CHAIN_FILE).unlink(missing_ok=True)

    agent_id = uuid7()
    session_442 = uuid7()
    session_589 = uuid7()
    session_103 = uuid7()
    supervisor_agent_id = uuid7()

    writer = ChainWriter(CHAIN_FILE, agent_id=agent_id)

    print("\n═══════════════════════════════════════════════════")
    print("  AHP Demo: Customer Support Agent")
    print("═══════════════════════════════════════════════════\n")

    # --- Record 1: BootRecord ---
    print("[startup]  Agent initializing...")
    writer.write_record(BootPayload(
        sdk_name="ahp-python",
        sdk_version="0.1.0",
        interceptors=["http", "mcp"],
        agent_name="support-bot",
        runtime="python 3.12",
        chain_level=ChainLevel.LEVEL_1,
        fsync_mode=FsyncMode.BATCH,
        inference_recording=True,
        authorization_recording=True,
    ))
    print("[startup]  BootRecord emitted. Recording policy active.\n")
    time.sleep(0.3)

    # ============================================================
    # Customer #442: "I was charged twice for my order"
    # ============================================================
    print("───────────────────────────────────────────────────")
    print("  Customer #442: \"I was charged twice for my order\"")
    print("───────────────────────────────────────────────────\n")
    time.sleep(0.3)

    # Record 2: INFERENCE — LLM decides to search orders
    print("[09:01:15] 🧠 INFERENCE → claude-sonnet-4-6")
    print("           \"Let me look up this customer's orders...\"")
    inference_1 = writer.write_record(ActionPayload(
        tool_name="anthropic.messages",
        parameters_hash=_hash16('{"messages":[{"role":"user","content":"Customer 442 says charged twice"}]}'),
        result_hash=_hash16('{"tool_use":"search_orders","input":{"customer_id":442}}'),
        result_status=ResultStatus.SUCCESS,
        response_time_ms=1200,
        protocol=Protocol.HTTP,
        action_type=ActionType.INFERENCE,
        model_id="claude-sonnet-4-6",
        input_token_count=1500,
        output_token_count=800,
        authorization=Authorization(type=AuthorizationType.AUTH_NONE),
    ), session_id=session_442)
    time.sleep(0.2)

    # Record 3: TOOL_CALL — search_orders (caused by inference)
    print("[09:01:16] 🔧 TOOL_CALL → search_orders(customer_id=442) → SUCCESS")
    writer.write_record(ActionPayload(
        parent_action_id=inference_1.record_id,
        tool_name="search_orders",
        parameters_hash=_hash16('{"customer_id":442}'),
        result_hash=_hash16('[{"order":7891,"amount":49.99},{"order":7891,"amount":49.99}]'),
        result_status=ResultStatus.SUCCESS,
        response_time_ms=42,
        protocol=Protocol.MCP,
        action_type=ActionType.TOOL_CALL,
        target_entity="orders_db",
        authorization=Authorization(type=AuthorizationType.AUTH_NONE),
    ), session_id=session_442)
    time.sleep(0.2)

    # Record 4: INFERENCE — LLM decides to refund
    print("[09:01:16] 🧠 INFERENCE → claude-sonnet-4-6")
    print("           \"Duplicate charge found. I'll process a refund.\"")
    inference_2 = writer.write_record(ActionPayload(
        parent_action_id=inference_1.record_id,
        tool_name="anthropic.messages",
        parameters_hash=_hash16('{"messages":[...search results show duplicate charge...]}'),
        result_hash=_hash16('{"tool_use":"process_refund","input":{"order":7891,"amount":49.99}}'),
        result_status=ResultStatus.SUCCESS,
        response_time_ms=800,
        protocol=Protocol.HTTP,
        action_type=ActionType.INFERENCE,
        model_id="claude-sonnet-4-6",
        input_token_count=2100,
        output_token_count=600,
        authorization=Authorization(type=AuthorizationType.AUTH_NONE),
    ), session_id=session_442)
    time.sleep(0.2)

    # Record 5: TOOL_CALL — process_refund (HUMAN APPROVED)
    print("[09:01:17] ⏳ Refund requires human approval...")
    time.sleep(0.5)
    print("[09:01:22] ✅ john@ops approved refund for $49.99")
    print("[09:01:22] 🔧 TOOL_CALL → process_refund(order=7891, $49.99) → SUCCESS")
    writer.write_record(ActionPayload(
        parent_action_id=inference_2.record_id,
        tool_name="process_refund",
        parameters_hash=_hash16('{"order":7891,"amount":49.99}'),
        result_hash=_hash16('{"refund_id":"RF-20260317-001","status":"processed"}'),
        result_status=ResultStatus.SUCCESS,
        response_time_ms=156,
        protocol=Protocol.MCP,
        action_type=ActionType.TOOL_CALL,
        target_entity="payment_api",
        authorization=Authorization(
            type=AuthorizationType.AUTH_HUMAN,
            entries=[AuthorizationEntry(
                authorizer_type=AuthorizerType.AUTHORIZER_HUMAN,
                authorizer_id="user:john@ops",
                decision=AuthorizationDecision.APPROVED,
                timestamp_ms=int(time.time() * 1000),
            )],
        ),
    ), session_id=session_442)
    print()
    time.sleep(0.3)

    # ============================================================
    # Customer #589: "What's your return policy?"
    # ============================================================
    print("───────────────────────────────────────────────────")
    print("  Customer #589: \"What's your return policy?\"")
    print("───────────────────────────────────────────────────\n")
    time.sleep(0.3)

    # Record 6: INFERENCE
    print("[09:15:30] 🧠 INFERENCE → claude-sonnet-4-6")
    print("           \"Simple question, let me search docs...\"")
    inference_3 = writer.write_record(ActionPayload(
        tool_name="anthropic.messages",
        parameters_hash=_hash16('{"messages":[{"role":"user","content":"return policy?"}]}'),
        result_hash=_hash16('{"tool_use":"search_docs","input":{"query":"return policy"}}'),
        result_status=ResultStatus.SUCCESS,
        response_time_ms=900,
        protocol=Protocol.HTTP,
        action_type=ActionType.INFERENCE,
        model_id="claude-sonnet-4-6",
        input_token_count=800,
        output_token_count=400,
        authorization=Authorization(type=AuthorizationType.AUTH_NONE),
    ), session_id=session_589)
    time.sleep(0.2)

    # Record 7: TOOL_CALL — search_docs
    print("[09:15:31] 🔧 TOOL_CALL → search_docs(\"return policy\") → SUCCESS")
    writer.write_record(ActionPayload(
        parent_action_id=inference_3.record_id,
        tool_name="search_docs",
        parameters_hash=_hash16('{"query":"return policy"}'),
        result_hash=_hash16('Returns allowed within 30 days of purchase...'),
        result_status=ResultStatus.SUCCESS,
        response_time_ms=38,
        protocol=Protocol.MCP,
        action_type=ActionType.TOOL_CALL,
        target_entity="docs_index",
        authorization=Authorization(type=AuthorizationType.AUTH_NONE),
    ), session_id=session_589)
    time.sleep(0.2)

    # Record 8: MESSAGE — reply to customer
    print("[09:15:31] 💬 MESSAGE → reply_customer → SUCCESS")
    writer.write_record(ActionPayload(
        parent_action_id=inference_3.record_id,
        tool_name="reply_customer",
        parameters_hash=_hash16('{"customer":589,"message":"Our return policy allows..."}'),
        result_hash=_hash16('{"status":"sent"}'),
        result_status=ResultStatus.SUCCESS,
        response_time_ms=5,
        protocol=Protocol.MCP,
        action_type=ActionType.MESSAGE,
        target_entity="customer:589",
        authorization=Authorization(type=AuthorizationType.AUTH_NONE),
    ), session_id=session_589)
    print()
    time.sleep(0.3)

    # ============================================================
    # Customer #103: "Delete my account and all my data"
    # ============================================================
    print("───────────────────────────────────────────────────")
    print("  Customer #103: \"Delete my account and all my data\"")
    print("───────────────────────────────────────────────────\n")
    time.sleep(0.3)

    # Record 9: INFERENCE — LLM recognizes destructive action
    print("[09:32:10] 🧠 INFERENCE → claude-sonnet-4-6")
    print("           \"Account deletion is destructive. Need multi-party approval.\"")
    inference_4 = writer.write_record(ActionPayload(
        tool_name="anthropic.messages",
        parameters_hash=_hash16('{"messages":[{"role":"user","content":"delete my account"}]}'),
        result_hash=_hash16('{"tool_use":"delete_account","input":{"user_id":103},"requires_approval":true}'),
        result_status=ResultStatus.SUCCESS,
        response_time_ms=1100,
        protocol=Protocol.HTTP,
        action_type=ActionType.INFERENCE,
        model_id="claude-sonnet-4-6",
        input_token_count=1200,
        output_token_count=500,
        authorization=Authorization(type=AuthorizationType.AUTH_NONE),
    ), session_id=session_103)
    time.sleep(0.2)

    # Record 10: TOOL_CALL — delete_account (MULTI-PARTY: supervisor + human)
    print("[09:32:11] ⏳ Deletion requires supervisor agent + human approval...")
    time.sleep(0.3)
    print("[09:32:11] 🤖 supervisor-bot: APPROVED (safety check passed)")
    time.sleep(0.3)
    print("[09:32:15] ✅ john@ops: APPROVED")
    print("[09:32:15] 🔧 TOOL_CALL → delete_account(user_id=103) → SUCCESS")
    writer.write_record(ActionPayload(
        parent_action_id=inference_4.record_id,
        tool_name="delete_account",
        parameters_hash=_hash16('{"user_id":103}'),
        result_hash=_hash16('{"status":"deleted","user_id":103,"gdpr_compliant":true}'),
        result_status=ResultStatus.SUCCESS,
        response_time_ms=203,
        protocol=Protocol.MCP,
        action_type=ActionType.TOOL_CALL,
        target_entity="user:103",
        authorization=Authorization(
            type=AuthorizationType.AUTH_MULTI_PARTY,
            entries=[
                AuthorizationEntry(
                    authorizer_type=AuthorizerType.AUTHORIZER_AGENT,
                    authorizer_id="supervisor-bot",
                    authorizer_agent_id=supervisor_agent_id,
                    authorizer_seq=847,
                    decision=AuthorizationDecision.APPROVED,
                    timestamp_ms=int(time.time() * 1000) - 4000,
                ),
                AuthorizationEntry(
                    authorizer_type=AuthorizerType.AUTHORIZER_HUMAN,
                    authorizer_id="user:john@ops",
                    decision=AuthorizationDecision.APPROVED,
                    timestamp_ms=int(time.time() * 1000),
                ),
            ],
        ),
    ), session_id=session_103)

    print(f"\n{'═' * 51}")
    print(f"  Chain written: {CHAIN_FILE}")
    print(f"  Records: {writer.record_count}")
    print(f"  Agent: support-bot ({agent_id.hex()[:16]}...)")
    print(f"{'═' * 51}\n")
    print("Try:")
    print(f"  python -m ahp.cli.main log --chain {CHAIN_FILE}")
    print(f"  python -m ahp.cli.main verify --chain {CHAIN_FILE}")
    print(f"  python -m ahp.cli.main show 5 --chain {CHAIN_FILE}")
    print()


if __name__ == '__main__':
    main()
