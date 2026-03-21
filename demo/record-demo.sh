#!/bin/bash
# AHP Demo — Full walkthrough: Install → Run → Record → Report
set -e

BOLD="\033[1m"
DIM="\033[2m"
CYAN="\033[36m"
GREEN="\033[32m"
RESET="\033[0m"

step() {
    echo ""
    echo -e "${CYAN}${BOLD}▶ $1${RESET}"
    echo -e "${DIM}$ $2${RESET}"
    sleep 1
    eval "$2"
    sleep 0.5
}

echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  AHP — Agent History Protocol${RESET}"
echo -e "${BOLD}  Full Demo: Install → Run Agents → View Records → Verify${RESET}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${RESET}"
sleep 2

# ─── PART 1: INSTALLATION ───────────────────────────────────────────
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  PART 1: Installation${RESET}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${RESET}"
sleep 1

step "Install AHP SDK" \
     "pip3 install open-ahp 2>&1 | tail -1"

step "Verify installation" \
     "python3 -c \"import ahp; print(f'AHP SDK v{ahp.__version__} installed successfully')\""

step "Check CLI is available" \
     "python3 -m ahp.cli.main --help"

sleep 1

# ─── PART 2: RUN AGENT SYSTEM ───────────────────────────────────────
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  PART 2: Run Multi-Agent System with Real LLM${RESET}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${RESET}"
sleep 1

echo ""
echo -e "${DIM}  Running 3 scenarios with real Gemini Flash API:${RESET}"
echo -e "${DIM}    1. Simple query (AUTH_NONE)${RESET}"
echo -e "${DIM}    2. Refund request (AUTH_AGENT — supervisor approval)${RESET}"
echo -e "${DIM}    3. Account deletion (AUTH_MULTI_PARTY — supervisor + human)${RESET}"
sleep 2

python3 demo/showcase/run.py

sleep 2

# ─── PART 3: INSPECT CHAIN RECORDS ─────────────────────────────────
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  PART 3: Inspect Chain Records${RESET}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${RESET}"
sleep 1

step "Show chain files on disk" \
     "ls -lh chains/*.ahp"

step "View a specific record in detail (record #7 — refund with AUTH_AGENT)" \
     "python3 -m ahp.cli.main show 7 --chain chains/support-bot.ahp"

sleep 1

step "Export chain to JSON" \
     "python3 -m ahp.cli.main export --chain chains/support-bot.ahp | head -3"

sleep 1

# ─── PART 4: VERIFICATION & COMPLIANCE ─────────────────────────────
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  PART 4: Verification & Compliance Report${RESET}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${RESET}"
sleep 1

step "Verify both agent chains" \
     "python3 -m ahp.cli.main verify --chain chains/support-bot.ahp && python3 -m ahp.cli.main verify --chain chains/supervisor-bot.ahp"

step "Check for gaps in the chain" \
     "python3 -m ahp.cli.main gaps --chain chains/support-bot.ahp"

step "Supervisor chain — A2A authorization decisions" \
     "python3 -m ahp.cli.main log --chain chains/supervisor-bot.ahp"

step "Filter: show only authorized actions (support-bot)" \
     "python3 -m ahp.cli.main log --chain chains/support-bot.ahp --authorized-by supervisor-bot"

step "Filter: show unauthorized actions (support-bot)" \
     "python3 -m ahp.cli.main log --chain chains/support-bot.ahp --unauthorized"

sleep 2

echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${RESET}"
echo -e "${GREEN}${BOLD}  Demo Complete${RESET}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${RESET}"
echo ""
echo -e "  ${BOLD}AHP — A flight recorder for AI agents.${RESET}"
echo -e "  ${DIM}github.com/iamanandsingh/agent-history-protocol${RESET}"
echo ""
sleep 3
