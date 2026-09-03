#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Integration scenario: threshold-CKKS — actor-shell + aggregator + contracts
# ═══════════════════════════════════════════════════════════════════════════════
#
# Covers the CKKS splice end-to-end at every layer that exists today:
#
#   1. ACTOR SHELL — real `ThresholdKeyshare` actix actors (scheme-dispatched
#      via SchemeParams) run the full CKKS DKG over the event bus: ephemeral
#      keys -> encrypted dealt rows (ThresholdShare events) -> joint pk
#      (KeyshareCreated) -> decryption shares (DecryptionshareCreated),
#      plus mid-DKG crash recovery from the persisted machine snapshot.
#   2. KEYSHARE CAPABILITY — workflow, encrypted transport, C2 proof gate
#      (tamper rejection), machine network, scheme dispatch.
#   3. AGGREGATOR — t+1 share combination to canonical fixed-point bytes,
#      byte-identical across different committee subsets.
#   4. NODE JOBS — e3-trckks payload pipeline + slot-batched auction
#      program (log-round bracket) + policies.
#   5. CONTRACTS — CkksFixedPointLib decodes the Rust encoder's bytes
#      (cross-language fixture pinned on both sides).
#
# HONEST BOUNDARY: this does NOT yet start chain-connected ciphernode
# processes (`base.sh` style). That requires an on-chain CKKS E3 request:
# `E3Requested` carries ABI-encoded BFV params today, so a process-level
# CKKS round needs the request/program contracts to carry CKKS params (and
# a CKKS `fake_encrypt` counterpart). The Rust side is ready for it —
# `SchemeParams::from_encoded` already dispatches on the params bytes the
# event carries.
#
# Usage: ./tests/integration/ckks.sh [--skip-contracts]
# ═══════════════════════════════════════════════════════════════════════════════

set -eu

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ROOT_DIR="$( cd "$THIS_DIR/../.." && pwd )"

SKIP_CONTRACTS=false
[[ "${1:-}" == "--skip-contracts" ]] && SKIP_CONTRACTS=true

cd "$ROOT_DIR"

echo "═══ [1/5] Actor shell: real actix actors, CKKS DKG + recovery ═══"
cargo test -p e3-keyshare ckks_shell --release -- --nocapture 2>&1 \
  | grep -E "^test |test result"

echo "═══ [2/5] Keyshare capability: workflow + transport + proofs + machine ═══"
cargo test -p e3-keyshare threshold_keyshare_ckks --release 2>&1 \
  | grep -E "^test |test result"

echo "═══ [3/5] Aggregator: subset-independent on-chain bytes ═══"
cargo test -p e3-aggregator ckks --release 2>&1 \
  | grep -E "^test |test result"

echo "═══ [4/5] Node jobs: e3-trckks pipeline + slot-batched auction ═══"
cargo test -p e3-trckks --release 2>&1 | grep -E "test result"

if [ "$SKIP_CONTRACTS" = false ]; then
  echo "═══ [5/5] Contracts: CkksFixedPointLib cross-language fixture ═══"
  (cd packages/interfold-contracts \
    && npx hardhat test mocha test/CkksFixedPointLib.spec.ts 2>&1 \
    | grep -E "✔|passing|failing")
else
  echo "═══ [5/5] Contracts: SKIPPED (--skip-contracts) ═══"
fi

echo ""
echo "═══ CKKS integration scenario complete ✅ ═══"
exit 0
