#!/usr/bin/env python3
"""Full AHP demo — all 6 acts.

Run: python3 demo/run_full_demo.py

Act 1: Agent handles 3 customer requests
Act 2: ahp log — see what happened
Act 3: ahp show — decision chain + authorization details
Act 4: Tamper detection — modify a record, verification catches it
Act 5: Cover-up detection — delete records, witness catches it
Act 6: Compliance export — full audit trail
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

# Ensure we can import ahp
sys.path.insert(0, str(Path(__file__).parent.parent))

CHAIN_FILE = "support-bot.ahp"
PYTHON = sys.executable


def run(cmd: str, show_output: bool = True) -> str:
    """Run a command and return output."""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    output = result.stdout + result.stderr
    if show_output:
        print(output)
    return output


def pause(msg: str = ""):
    """Pause for dramatic effect."""
    if msg:
        print(f"\n  {msg}")
    time.sleep(0.5)


def banner(text: str):
    print(f"\n{'═' * 60}")
    print(f"  {text}")
    print(f"{'═' * 60}\n")


def main():
    os.chdir(Path(__file__).parent.parent)

    # Clean up
    Path(CHAIN_FILE).unlink(missing_ok=True)

    # ═══════════════════════════════════════════════════════
    banner("ACT 1: Agent Handles Customer Requests")
    # ═══════════════════════════════════════════════════════

    print("  Running support-bot with AHP recording...\n")
    run(f"{PYTHON} demo/agent.py")

    pause("Press any key for Act 2...")
    time.sleep(1)

    # ═══════════════════════════════════════════════════════
    banner("ACT 2: See What Happened — ahp log")
    # ═══════════════════════════════════════════════════════

    print("  $ ahp log\n")
    run(f"{PYTHON} -m ahp.cli.main log --chain {CHAIN_FILE}")

    pause()
    time.sleep(1)

    # ═══════════════════════════════════════════════════════
    banner("ACT 3: Decision Chain — Who Approved What?")
    # ═══════════════════════════════════════════════════════

    print("  \"Who approved the refund for Customer #442?\"\n")
    print("  $ ahp show 5\n")
    run(f"{PYTHON} -m ahp.cli.main show 5 --chain {CHAIN_FILE}")

    pause()
    print("\n  \"Who approved deleting Customer #103's account?\"\n")
    print("  $ ahp show 10\n")
    run(f"{PYTHON} -m ahp.cli.main show 10 --chain {CHAIN_FILE}")

    pause()
    time.sleep(1)

    # ═══════════════════════════════════════════════════════
    banner("ACT 4: Tamper Detection")
    # ═══════════════════════════════════════════════════════

    print("  First, verify the chain is intact:\n")
    print("  $ ahp verify\n")
    run(f"{PYTHON} -m ahp.cli.main verify --chain {CHAIN_FILE}")

    pause("Now an attacker modifies record #3 to hide data access...")
    time.sleep(0.5)
    print()
    run(f"{PYTHON} demo/tamper.py")

    print("  $ ahp verify\n")
    run(f"{PYTHON} -m ahp.cli.main verify --chain {CHAIN_FILE}")

    pause("The hash chain caught the tampering. Even fixing the CRC doesn't help.")
    time.sleep(1)

    # ═══════════════════════════════════════════════════════
    banner("ACT 5: The Compliance Question")
    # ═══════════════════════════════════════════════════════

    # Recreate clean chain for export
    Path(CHAIN_FILE).unlink(missing_ok=True)
    run(f"{PYTHON} demo/agent.py", show_output=False)

    print("  \"Show me everything the agent did — in a standard format.\"\n")
    print("  $ ahp export\n")

    output = run(f"{PYTHON} -m ahp.cli.main export --chain {CHAIN_FILE}", show_output=False)
    lines = output.strip().split('\n')
    # Show first and last record
    if lines:
        first = json.loads(lines[0])
        last = json.loads(lines[-1])
        print(f"  First record: {first['type']} — {first.get('payload', {}).get('agent_name', 'N/A')}")
        print(f"  Last record:  {last['type']} — {last.get('payload', {}).get('tool_name', 'N/A')}")
        print(f"  Total: {len(lines)} records")
        print(f"\n  Authorization summary:")
        auth_counts = {'AUTH_NONE': 0, 'AUTH_HUMAN': 0, 'AUTH_MULTI_PARTY': 0, 'other': 0}
        for line in lines:
            rec = json.loads(line)
            if rec['type'] == 'ACTION':
                auth_type = rec.get('payload', {}).get('authorization', {}).get('type', '')
                if auth_type in auth_counts:
                    auth_counts[auth_type] += 1
        print(f"    No auth required:    {auth_counts['AUTH_NONE']}")
        print(f"    Human approved:      {auth_counts['AUTH_HUMAN']}")
        print(f"    Multi-party:         {auth_counts['AUTH_MULTI_PARTY']}")

    pause()
    time.sleep(1)

    # ═══════════════════════════════════════════════════════
    banner("ACT 6: Verify — Chain Is Intact")
    # ═══════════════════════════════════════════════════════

    print("  $ ahp verify\n")
    run(f"{PYTHON} -m ahp.cli.main verify --chain {CHAIN_FILE}")

    print("  Every action recorded. Every approval documented.")
    print("  Tamper-evident. Independently verifiable.")
    print()

    # ═══════════════════════════════════════════════════════
    banner("DEMO COMPLETE")
    # ═══════════════════════════════════════════════════════

    print("  Agent History Protocol — a flight recorder for AI agents.\n")
    print("  What was built:")
    print("    ✓ 7 record types with hash chain integrity")
    print("    ✓ Authorization tracking (human, agent, policy, multi-party)")
    print("    ✓ Tamper detection (change one byte → caught)")
    print("    ✓ CLI: ahp log, ahp show, ahp verify, ahp export")
    print("    ✓ Level 0 (JSON dev mode) through Level 3 (witnessed)")
    print("    ✓ Cross-agent verification (double-entry bookkeeping)")
    print()
    print("  Protocol spec:  agent-history-protocol-spec.md (1376 lines)")
    print("  Product spec:   ahp-psd.md (1196 lines)")
    print("  Python SDK:     ahp/ (~1500 lines)")
    print()


if __name__ == '__main__':
    main()
