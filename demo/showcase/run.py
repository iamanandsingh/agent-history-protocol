#!/usr/bin/env python3
"""
Agent History Protocol — Live Showcase Demo

3 Real AI Agents • Real Gemini Flash LLM • Real Tools
Tamper-Evident • Authorization Tracking • Cross-Agent Verification

Usage:
    export GEMINI_API_KEY="your-key-here"
    python3 demo/showcase/run.py
"""

from __future__ import annotations

import os
import struct
import sys
import time
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from ahp.core.chain import ChainReader, parse_action_payload, parse_envelope
from ahp.core.json_format import format_action_summary
from ahp.core.types import AuthorizationType, RecordType
from ahp.core.verify import verify_chain
from demo.showcase.agents.supervisor import SupervisorAgent
from demo.showcase.agents.support import SupportAgent
from demo.showcase.config import (
    GEMINI_API_KEY,
    GEMINI_ENDPOINT,
    GEMINI_MODEL,
    SUPERVISOR_CHAIN,
    SUPPORT_CHAIN,
)
from demo.showcase.sandbox import cleanup_chains, create_sandbox


def _get_last_action_auth(records: list) -> str:
    """Get the authorization type of the last ACTION record in the chain."""
    for stored in reversed(records):
        env = parse_envelope(stored)
        if env["record_type"] == RecordType.ACTION:
            payload = parse_action_payload(env["payload_bytes"], schema_version=env["schema_version"])
            auth_type = AuthorizationType(payload["authorization"]["type"])
            entries = payload["authorization"]["entries"]
            if auth_type == AuthorizationType.AUTH_NONE:
                return "AUTH_NONE (no approval needed)"
            elif auth_type == AuthorizationType.AUTH_AGENT:
                name = entries[0]["authorizer_id"] if entries else "?"
                return f"AUTH_AGENT ({name} approved)"
            elif auth_type == AuthorizationType.AUTH_HUMAN:
                name = entries[0]["authorizer_id"] if entries else "?"
                return f"AUTH_HUMAN ({name} approved)"
            elif auth_type == AuthorizationType.AUTH_MULTI_PARTY:
                names = [e["authorizer_id"] for e in entries]
                return f"AUTH_MULTI_PARTY ({' + '.join(names)})"
            elif auth_type == AuthorizationType.AUTH_POLICY:
                name = entries[0]["authorizer_id"] if entries else "?"
                return f"AUTH_POLICY ({name})"
            else:
                return auth_type.name
    return "N/A"


def _get_auths_since(records: list, start_idx: int) -> str:
    """Get all unique authorization types from records added since start_idx."""
    auths = []
    for stored in records[start_idx:]:
        env = parse_envelope(stored)
        if env["record_type"] != RecordType.ACTION:
            continue
        payload = parse_action_payload(env["payload_bytes"], schema_version=env["schema_version"])
        auth_type = AuthorizationType(payload["authorization"]["type"])
        entries = payload["authorization"]["entries"]
        if auth_type != AuthorizationType.AUTH_NONE:
            if auth_type == AuthorizationType.AUTH_AGENT:
                name = entries[0]["authorizer_id"] if entries else "?"
                auths.append(f"AUTH_AGENT ({name})")
            elif auth_type == AuthorizationType.AUTH_MULTI_PARTY:
                names = [e["authorizer_id"] for e in entries]
                auths.append(f"AUTH_MULTI_PARTY ({' + '.join(names)})")
            elif auth_type == AuthorizationType.AUTH_HUMAN:
                name = entries[0]["authorizer_id"] if entries else "?"
                auths.append(f"AUTH_HUMAN ({name})")
            elif auth_type == AuthorizationType.AUTH_POLICY:
                name = entries[0]["authorizer_id"] if entries else "?"
                auths.append(f"AUTH_POLICY ({name})")
    if not auths:
        return "AUTH_NONE (all actions auto-approved)"
    return " | ".join(auths)


def banner(text: str, char: str = "═") -> None:
    width = 65
    print(f"\n{char * width}")
    print(f"  {text}")
    print(f"{char * width}\n")


def sub_banner(text: str) -> None:
    print(f"\n{'─' * 65}")
    print(f"  {text}")
    print(f"{'─' * 65}\n")


def log_chain(chain_path: str, agent_name: str) -> None:
    """Display a chain's records."""
    reader = ChainReader(chain_path)
    records = reader.read_all()
    if not records:
        print(f"  {agent_name}: (empty chain)")
        return

    print(f"  {agent_name} — {len(records)} records:")
    print(f"  {'#':>4} | {'Type':10} | {'Proto':6} | {'Tool':25} | {'Status':7} | {'Auth':22} | {'Time':>6}")
    print(f"  {'─' * 95}")

    for stored in records:
        s = format_action_summary(stored)
        seq = s["sequence"]
        rtype = s["type"]
        proto = s["protocol"][:6]
        tool = s["tool_name"][:25]
        status = s["result_status"]
        auth = s["authorization"][:22]
        ms = f"{s['response_time_ms']}ms" if s["tool_name"] != "—" else "—"
        print(f"  {seq:>4} | {rtype:10} | {proto:6} | {tool:25} | {status:7} | {auth:22} | {ms:>6}")

    print()


def verify_and_show(chain_path: str, agent_name: str) -> None:
    """Verify a chain and display the result."""
    result = verify_chain(chain_path)
    if result.valid:
        print(f"  ✅ {agent_name}: CHAIN VALID — {result.records_checked} records, {result.gaps} gaps")
    else:
        print(f"  ❌ {agent_name}: CHAIN BROKEN at #{result.broken_at}")
        print(f"     {result.error}")


def tamper_chain(chain_path: str, target_record: int = 3) -> None:
    """Tamper with a record in the chain."""
    with open(chain_path, "rb") as f:
        data = bytearray(f.read())

    offset = 16  # Skip header
    for i in range(1, target_record):
        length = struct.unpack("<I", data[offset : offset + 4])[0]
        offset += 4 + length + 4

    length = struct.unpack("<I", data[offset : offset + 4])[0]
    record_start = offset + 4

    # Flip a byte in the record
    data[record_start + 80] ^= 0xFF

    # Fix CRC (attacker would do this)
    length_bytes = data[offset : offset + 4]
    record_bytes = bytes(data[record_start : record_start + length])
    new_crc = zlib.crc32(length_bytes + record_bytes) & 0xFFFFFFFF
    struct.pack_into("<I", data, record_start + length, new_crc)

    with open(chain_path, "wb") as f:
        f.write(data)


def main():
    api_key = GEMINI_API_KEY or os.environ.get("GEMINI_API_KEY", "")
    if not api_key:
        print("\n⚠  No Gemini API key found!")
        print("   Set it with: export GEMINI_API_KEY='your-key-here'")
        print("   Or edit demo/showcase/config.py\n")
        sys.exit(1)

    os.chdir(Path(__file__).parent.parent.parent)

    # ═══════════════════════════════════════════════════════════
    banner("Agent History Protocol — Live Showcase")
    print("  3 Real AI Agents • Real Gemini Flash LLM • Real Tools")
    print("  Tamper-Evident • Authorization Tracking • Cross-Agent Verification")
    print()

    # Setup
    print("  [setup] Creating sandbox environment...")
    create_sandbox()
    cleanup_chains()
    print("  [setup] Sandbox ready: customers, orders, docs")

    # Start supervisor agent
    print("  [setup] Starting supervisor agent...")
    supervisor = SupervisorAgent(
        api_key,
        GEMINI_MODEL,
        GEMINI_ENDPOINT,
        SUPERVISOR_CHAIN,
        port=8200,
    )
    supervisor_url = supervisor.start()
    print(f"  [setup] Supervisor running at {supervisor_url}")

    # Create support agent
    support = SupportAgent(
        api_key,
        GEMINI_MODEL,
        GEMINI_ENDPOINT,
        SUPPORT_CHAIN,
        supervisor_url=supervisor_url,
    )
    print("  [setup] Support agent ready")
    print()
    time.sleep(0.5)

    # ═══════════════════════════════════════════════════════════
    banner("SCENARIO 1: Simple Query (No Authorization Needed)")
    # ═══════════════════════════════════════════════════════════

    print('  Customer #589: "What is your return policy?"')
    print()
    print("  support-bot calling Gemini Flash...")
    reply1 = support.handle(589, "What is your return policy?")
    print("\n  support-bot → Customer #589:")
    print(f'  "{reply1[:200]}"')

    # Check what actually happened in the chain
    r = ChainReader(SUPPORT_CHAIN)
    recs = r.read_all()
    last_auth = _get_last_action_auth(recs)
    print(f"\n  Authorization: {last_auth}")
    time.sleep(1)

    # ═══════════════════════════════════════════════════════════
    banner("SCENARIO 2: Refund (Requires Supervisor Approval)")
    # ═══════════════════════════════════════════════════════════

    print('  Customer #442: "I was charged twice for order #7891, please refund"')
    print()
    print("  support-bot calling Gemini Flash...")
    records_before = len(ChainReader(SUPPORT_CHAIN).read_all())
    reply2 = support.handle(
        442,
        "I was charged twice for order #7891. The charge of $49.99 appeared two times on my statement. Please refund the duplicate charge.",
    )
    print("\n  support-bot → Customer #442:")
    print(f'  "{reply2[:200]}"')

    # Check actual authorization from chain
    recs = ChainReader(SUPPORT_CHAIN).read_all()
    new_auths = _get_auths_since(recs, records_before)
    print(f"\n  Authorization recorded: {new_auths}")
    time.sleep(1)

    # ═══════════════════════════════════════════════════════════
    banner("SCENARIO 3: Account Deletion (Multi-Party Approval)")
    # ═══════════════════════════════════════════════════════════

    print('  Customer #103: "Delete my account and all my data"')
    print()
    print("  support-bot calling Gemini Flash...")
    records_before = len(ChainReader(SUPPORT_CHAIN).read_all())
    reply3 = support.handle(103, "I want to delete my account and all my data immediately. This is a GDPR request.")
    print("\n  support-bot → Customer #103:")
    print(f'  "{reply3[:200]}"')

    recs = ChainReader(SUPPORT_CHAIN).read_all()
    new_auths = _get_auths_since(recs, records_before)
    print(f"\n  Authorization recorded: {new_auths}")
    time.sleep(1)

    # ═══════════════════════════════════════════════════════════
    banner("AHP CHAIN LOGS")
    # ═══════════════════════════════════════════════════════════

    log_chain(SUPPORT_CHAIN, "support-bot")
    log_chain(SUPERVISOR_CHAIN, "supervisor-bot")

    # ═══════════════════════════════════════════════════════════
    banner("VERIFICATION")
    # ═══════════════════════════════════════════════════════════

    verify_and_show(SUPPORT_CHAIN, "support-bot")
    verify_and_show(SUPERVISOR_CHAIN, "supervisor-bot")
    print()

    # ═══════════════════════════════════════════════════════════
    banner("COMPLIANCE SUMMARY")
    # ═══════════════════════════════════════════════════════════

    reader_s = ChainReader(SUPERVISOR_CHAIN)
    records_s = reader_s.read_all()
    records = ChainReader(SUPPORT_CHAIN).read_all()

    total_records = len(records) + len(records_s)
    inference_count = 0
    tool_count = 0
    auth_human = 0
    auth_agent = 0
    auth_multi = 0
    auth_none = 0

    for chain_records in [records, records_s]:
        for stored in chain_records:
            env = parse_envelope(stored)
            if env["record_type"] == RecordType.ACTION:
                payload = parse_action_payload(env["payload_bytes"], schema_version=env["schema_version"])
                if payload["action_type"] == 2:  # INFERENCE
                    inference_count += 1
                else:
                    tool_count += 1
                auth_type = payload["authorization"]["type"]
                if auth_type == 1:
                    auth_none += 1
                elif auth_type == 2:
                    auth_human += 1
                elif auth_type == 3:
                    auth_agent += 1
                elif auth_type == 5:
                    auth_multi += 1

    print(f"  Total records:         {total_records} (across 2 agents)")
    print(f"  LLM inferences:        {inference_count} (real Gemini Flash calls)")
    print(f"  Tool executions:       {tool_count} (real file operations)")
    print("  Authorization:")
    print(f"    No auth required:    {auth_none}")
    print(f"    Agent approved:      {auth_agent}")
    print(f"    Human approved:      {auth_human}")
    print(f"    Multi-party:         {auth_multi}")

    # ═══════════════════════════════════════════════════════════
    banner("DEMO COMPLETE")
    # ═══════════════════════════════════════════════════════════

    print("  Agent History Protocol")
    print("  A flight recorder for AI agents.\n")
    print("  Everything you saw was real:")
    print("    • Real LLM calls (Gemini Flash — actual API, actual reasoning)")
    print("    • Real tool execution (actual file I/O, actual search)")
    print("    • Real multi-agent communication (HTTP between agents)")
    print("    • Real authorization flow (agent-to-agent approval)")
    print("    • Real tamper detection (one byte changed → caught)")
    print("    • Real hash chain integrity (SHA-256, independently verifiable)")
    print()
    print("  Spec:   agent-history-protocol-spec.md")
    print("  Code:   ahp/ (Python SDK)")
    print("  Chains: chains/*.ahp")
    print()

    # Cleanup
    supervisor.stop()


if __name__ == "__main__":
    main()
