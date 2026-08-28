#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Interfold CKKS E2E — Threshold CKKS demos, node integration, and ZK circuits
# ═══════════════════════════════════════════════════════════════════════════════
#
# What this runs (CRISP-style staged e2e, but for the CKKS stack):
#   1. fhe.rs crypto layer  — CKKS + threshold-CKKS unit tests (ops, relin,
#      DKG, flooding-bound calculator, threshold decryption)
#   2. Demo applications    — sealed-bid Vickrey auction + private statistics
#      (full DKG -> encrypt -> compute -> threshold decrypt, real output)
#   3. Node integration     — e3-trckks job-payload pipeline e2e tests
#      (serialized DKG dealing/aggregation, policies, threshold decryption)
#   4. ZK circuits          — regenerate witnesses with the checked-in codegen
#      and `nargo execute` all three CKKS circuits:
#        - user_data_encryption_ckks_ct0   (Greco-style encryption proof)
#        - decrypted_shares_aggregation_ckks (C7-CKKS share combine)
#        - sk_share_computation_ckks       (C2a verifiable DKG)
#   5. Noir test suite      — full circuits/lib nargo test run
#
# Usage:
#   ./scripts/ckks-e2e.sh                 # everything (~5-10 min)
#   ./scripts/ckks-e2e.sh --quick        # skip stage 1 (fhe.rs unit tests)
#   ./scripts/ckks-e2e.sh --demos-only   # only stage 2 (the two demos)
#   ./scripts/ckks-e2e.sh --circuits-only # only stages 4-5
#
# Requirements: cargo, nargo (1.0.0-beta.26), pnpm. The fhe.rs checkout must
# sit next to this repo at ../fhe.rs (the Cargo [patch] already points there).
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FHE_RS_DIR="${FHE_RS_DIR:-$REPO_ROOT/../fhe.rs}"

# ── Colors ───────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

say()  { echo -e "${GREEN}═══ $* ${NC}"; }
info() { echo -e "${BLUE}    $* ${NC}"; }
warn() { echo -e "${YELLOW}⚠️  $* ${NC}"; }
err()  { echo -e "${RED}❌ $* ${NC}"; }

# ── Flags ────────────────────────────────────────────────────────────────────
RUN_CRYPTO=true
RUN_DEMOS=true
RUN_NODE=true
RUN_CIRCUITS=true

for arg in "$@"; do
  case "$arg" in
    --quick)          RUN_CRYPTO=false ;;
    --demos-only)     RUN_CRYPTO=false; RUN_NODE=false; RUN_CIRCUITS=false ;;
    --circuits-only)  RUN_CRYPTO=false; RUN_DEMOS=false; RUN_NODE=false ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//' | head -30
      exit 0
      ;;
    *)
      err "Unknown argument: $arg (try --help)"
      exit 1
      ;;
  esac
done

# ── Pre-flight ───────────────────────────────────────────────────────────────
say "Pre-flight checks"

if [ ! -d "$FHE_RS_DIR/crates/fhe" ]; then
  err "fhe.rs checkout not found at $FHE_RS_DIR (set FHE_RS_DIR to override)"
  exit 1
fi
for tool in cargo nargo pnpm; do
  if ! command -v "$tool" &>/dev/null; then
    err "$tool is not installed"
    exit 1
  fi
done
info "fhe.rs:  $FHE_RS_DIR"
info "nargo:   $(nargo --version | head -1)"
echo ""

START_TS=$(date +%s)

# ── Stage 1: fhe.rs crypto layer ─────────────────────────────────────────────
if [ "$RUN_CRYPTO" = true ]; then
  say "Stage 1/5: fhe.rs crypto layer (ckks + trckks unit tests)"
  info "ops, relinearization, serialization, multiparty keygen,"
  info "multiparty relin-key gen, flooding-bound calculator, threshold decrypt"
  (cd "$FHE_RS_DIR" && cargo test -p fhe --lib -- ckks trckks 2>&1 \
    | grep -E "test result|running" | tail -2)
  echo ""
else
  warn "Stage 1/5 skipped (--quick / --demos-only / --circuits-only)"
  echo ""
fi

# ── Stage 2: demo applications ───────────────────────────────────────────────
if [ "$RUN_DEMOS" = true ]; then
  say "Stage 2/5: Sealed-bid auction demo (threshold CKKS)"
  info "5-party committee, DKG, encrypted bids, masked comparisons,"
  info "second-price opened — losing bids never decrypted"
  (cd "$FHE_RS_DIR" && cargo run --release --example trckks_auction)
  echo ""

  say "Stage 2/5: Private statistics demo (threshold CKKS)"
  info "encrypted measurements, homomorphic sum + relinearized sum-of-squares,"
  info "only the aggregates are threshold-decrypted"
  (cd "$FHE_RS_DIR" && cargo run --release --example trckks_statistics)
  echo ""
else
  warn "Stage 2/5 skipped (--circuits-only)"
  echo ""
fi

# ── Stage 3: node integration (e3-trckks) ────────────────────────────────────
if [ "$RUN_NODE" = true ]; then
  say "Stage 3/5: Node integration — e3-trckks job-payload pipeline"
  info "serialized DKG dealing -> share exchange -> aggregation -> policy"
  info "compute -> decryption shares -> threshold decryption, for all three"
  info "policies (sum, statistics, auction)"
  (cd "$REPO_ROOT" && cargo test -p e3-trckks --release 2>&1 \
    | grep -E "^test |test result: ok" )
  echo ""
else
  warn "Stage 3/5 skipped (--demos-only / --circuits-only)"
  echo ""
fi

# ── Stage 4: ZK circuits with fresh witnesses ────────────────────────────────
if [ "$RUN_CIRCUITS" = true ]; then
  say "Stage 4/5: ZK circuits — fresh witnesses + nargo execute"

  # Snapshot the checked-in generated configs so we can detect drift after
  # regeneration (works for both tracked and not-yet-committed files).
  CONFIG_FILES=(
    "$REPO_ROOT/circuits/lib/src/configs/ckks.nr"
    "$REPO_ROOT/circuits/lib/src/configs/ckks_aggregation.nr"
    "$REPO_ROOT/circuits/lib/src/configs/ckks_dkg.nr"
  )
  SNAPSHOT_DIR="$(mktemp -d)"
  trap 'rm -rf "$SNAPSHOT_DIR"' EXIT
  for f in "${CONFIG_FILES[@]}"; do
    cp "$f" "$SNAPSHOT_DIR/$(basename "$f")"
  done

  info "[1/3] user_data_encryption_ckks_ct0 (Greco-style encryption proof)"
  (cd "$REPO_ROOT" && cargo run -p e3-zk-helpers --example gen_ckks_prover 2>&1 | tail -1)
  (cd "$REPO_ROOT/circuits/bin/threshold/user_data_encryption_ckks_ct0" \
    && nargo execute 2>&1 | grep -E "successfully|saved" | head -1)

  info "[2/3] decrypted_shares_aggregation_ckks (C7-CKKS share combine)"
  (cd "$REPO_ROOT" && cargo run -p e3-zk-helpers --example gen_ckks_agg_prover 2>&1 | tail -1)
  (cd "$REPO_ROOT/circuits/bin/threshold/decrypted_shares_aggregation_ckks" \
    && nargo execute 2>&1 | grep -E "successfully|saved" | head -1)

  info "[3/3] sk_share_computation_ckks (C2a verifiable DKG)"
  (cd "$REPO_ROOT" && cargo run -p e3-zk-helpers --example gen_ckks_dkg_prover 2>&1 | tail -1)
  (cd "$REPO_ROOT/circuits/bin/dkg/sk_share_computation_ckks" \
    && nargo execute 2>&1 | grep -E "successfully|saved" | head -1)

  # Witness generators must not have drifted from the checked-in configs
  # (Prover.toml is fresh-random every run; the configs must be stable).
  # `nargo fmt` first: the repo's canonical form is codegen output + fmt.
  info "checking regenerated configs match the checked-in versions"
  (cd "$REPO_ROOT/circuits/lib" && nargo fmt)
  DRIFTED=false
  for f in "${CONFIG_FILES[@]}"; do
    if ! cmp -s "$f" "$SNAPSHOT_DIR/$(basename "$f")"; then
      err "Config drift in $(basename "$f") — codegen output changed."
      DRIFTED=true
    fi
  done
  if [ "$DRIFTED" = true ]; then
    err "Inspect the diffs; commit them if the change is intentional."
    exit 1
  fi
  echo ""

  # ── Stage 5: Noir test suite ───────────────────────────────────────────────
  say "Stage 5/5: Noir circuit test suite (circuits/lib)"
  (cd "$REPO_ROOT" && pnpm noir:test 2>&1 | tail -1)
  echo ""
else
  warn "Stages 4-5 skipped (--demos-only)"
  echo ""
fi

ELAPSED=$(( $(date +%s) - START_TS ))
say "CKKS E2E complete in ${ELAPSED}s ✅"
[ "$RUN_CRYPTO" = true ]   && info "crypto layer:      fhe.rs ckks + trckks tests green"
[ "$RUN_DEMOS" = true ]    && info "demos:             auction + statistics ran with real output"
[ "$RUN_NODE" = true ]     && info "node integration:  e3-trckks pipeline e2e green"
[ "$RUN_CIRCUITS" = true ] && info "zk circuits:       3/3 executed with fresh witnesses; noir suite green"
exit 0
