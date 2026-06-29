#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Interfold CCA Demo — FOLD Token + CCA Auction Rehearsal on Sepolia
# ═══════════════════════════════════════════════════════════════════════════════
#
# What this shows:
#   1. One script deploys MockBondingRegistry proxy + sale deployer
#   2. Deterministic address prediction (FOLD + CCA auction)
#   3. ONE transaction: deploySale() creates FOLD + Uniswap CCA atomically
#   4. Safe SDK proposes FOLD.acceptOwnership() to the Foundation Safe
#   5. ~20 on-chain validation assertions all pass
#   6. Bid → checkpoint → exit → claim flow with locked FOLD
#   7. Sale UI shows live phases (Virtual → CCA → Cooldown)
#
# Total duration: ~7-8 minutes (5 min auction + 2 min setup)
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONTRACTS_DIR="$REPO_ROOT/packages/interfold-contracts"
SALE_UI_DIR="$REPO_ROOT/packages/interfold-sale"

# ── Config ───────────────────────────────────────────────────────────────────
SAFE="0x27853b4E771061390477AD8d40826276b1F4BF2F"
RPC_URL="${RPC_URL:-https://ethereum-sepolia-rpc.publicnode.com}"
NETWORK="sepolia"
CCA_BLOCKS="25"              # ~5 minutes on Sepolia
CCA_OFFSET_SECONDS="60"      # FOLD CCA phase starts 60s after deploy
CCA_DURATION_SECONDS="600"   # FOLD CCA phase lasts 10 minutes (matches ~50 blocks)

# ── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

say() { echo -e "${GREEN}═══ $* ${NC}"; }
warn() { echo -e "${YELLOW}⚠️  $* ${NC}"; }
err() { echo -e "${RED}❌ $* ${NC}"; }

# ── Pre-flight checks ────────────────────────────────────────────────────────
say "Pre-flight checks..."

if [ -z "${PRIVATE_KEY:-}" ]; then
  err "PRIVATE_KEY is not set. Export it first:"
  echo "  export PRIVATE_KEY=0x..."
  echo ""
  echo "This is the operator wallet private key (pays gas, signs Safe proposal)."
  echo "It is NOT stored anywhere — only used in memory for this session."
  exit 1
fi

if ! command -v pnpm &>/dev/null; then
  err "pnpm is not installed. Install it first: npm install -g pnpm"
  exit 1
fi

# ── Step 1: Compile contracts ────────────────────────────────────────────────
say "Step 1/4: Compiling contracts..."
cd "$CONTRACTS_DIR"
pnpm compile
echo ""

# ── Step 2: Full test (prepare → plan → deploy → propose-safe → validate → bid-claim)
say "Step 2/4: Running full rehearsal..."
say "  - Deploying MockBondingRegistry proxy (Safe-owned)"
say "  - Deploying sale deployer"
say "  - Predicting FOLD + CCA addresses"
say "  - Submitting deploySale() — ONE transaction"
say "  - Proposing FOLD.acceptOwnership() to Safe"
say "  - Validating ~20 on-chain invariants"
say "  - Bidding → checkpoint → exit → claim"
echo ""

pnpm sale \
  --network "$NETWORK" \
  --action full-test \
  --safe "$SAFE" \
  --cca-offset-seconds "$CCA_OFFSET_SECONDS" \
  --cca-duration-seconds "$CCA_DURATION_SECONDS" \
  --auction-duration-blocks "$CCA_BLOCKS" \
  --propose-safe

say "Full rehearsal complete!"
echo ""

# ── Step 3: Start Sale UI ────────────────────────────────────────────────────
say "Step 3/4: Starting sale UI..."
cd "$SALE_UI_DIR"

if [ ! -d "node_modules" ]; then
  say "Installing UI dependencies..."
  pnpm install
fi

say "Sale UI starting at http://localhost:5173"
say "Open this in your browser NOW."
echo ""
say "What to show in the UI:"
say "  Overview tab:  FOLD phases (Virtual → CCA), CCA blocks, metrics"
say "  Auction tab:   Submit a bid, watch checkpoint/exit/claim"
say "  Token Lab:     Mint allocations, create lock policies, trigger TGE"
say "  Events:        All on-chain events in real time"
say "  Contracts:     All deployed addresses with Etherscan links"
echo ""

pnpm dev &
UI_PID=$!
echo ""

# ── Step 4: Safe UI link ────────────────────────────────────────────────────
say "Step 4/4: Safe transaction to execute"
echo ""
say "Open the Safe UI to show the pending FOLD.acceptOwnership() transaction."
say "Look for the URL printed after 'Safe transaction proposed' above."
say "It should be: https://app.safe.global/transactions/tx?safe=sep:${SAFE}&id=..."
echo ""

# ── Done ─────────────────────────────────────────────────────────────────────
say "═══════════════════════════════════════════"
say "CCA Demo — All systems ready"
say "═══════════════════════════════════════════"
echo ""
say "Talking points for the demo:"
echo ""
echo "  1. ONE TRANSACTION: deploySale() creates FOLD + Uniswap CCA atomically."
echo "     No multi-step deploy risk. Addresses predicted BEFORE deploy."
echo ""
echo "  2. SAFE-OWNED: The Foundation Safe is admin of everything."
echo "     The operator just pays gas — has zero FOLD roles."
echo ""
echo "  3. REAL UNISWAP CCA: We use the canonical Uniswap CCA factory at"
echo "     0xCCccCcCAE7503Cac057829BF2811De42E16e0bD5 on Sepolia."
echo "     Mainnet uses the SAME factory address."
echo ""
echo "  4. VALIDATED: ~20 on-chain assertions check FOLD/CCA/Safe invariants."
echo "     Script REFUSES to deploy if nonce moves."
echo ""
echo "  5. LOCKED CLAIMS: Claimed FOLD is transfer-restricted until TGE."
echo "     No front-running, no bot dumping."
echo ""
echo "  6. SAME FLOW ON MAINNET: Swap --network sepolia for --network mainnet,"
echo "     set real timestamps/blocks. That's it."
echo ""
say "Press Ctrl+C to stop the UI when done."

# Wait for UI process
wait $UI_PID 2>/dev/null || true
