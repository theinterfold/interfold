#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
#
# Full CKKS auction e2e in leak-free WINNER mode: anvil + deployed
# contracts + REAL ciphernode processes + REAL encrypted bids + ITERATED
# SIGN EXTRACTION.
#
# Differences from ckks-auction.sh (masked-difference mode):
#   - ParamSet 2: the sign-extraction ladder (45-bit base + 37x40-bit
#     limbs, delta 2^40) PLUS three 60-bit special primes for HYBRID key
#     switching. Its 45-bit base exceeds the standard DKG transport's
#     plaintext modulus, so the nodes deterministically escalate share
#     transport to InsecureDkgWide512 (the special primes are public key
#     material only — they never travel through the DKG).
#   - Nodes run ONE two-round multiparty HYBRID relin ceremony (derived by
#     every node from the E3's ParamSet — no configuration) and write the
#     single joint key to
#     <data_dir>/<node>/ckks/relin-keys/<chain:e3_id>/rlk_hybrid.bin.
#   - ckks_auction_eval --mode winner consumes that ONE ceremony key and
#     drives every i<j pair slot to EXACTLY ±1 (12 cubic iterations).
#   - The final assertion checks the winner AND that every opened slot is
#     a SATURATED ±1 sign — the output leaks the order and nothing else
#     (a 2% gap pair is included to prove gaps do not leak).

set -eu

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

source "$THIS_DIR/fns.sh"
source "$THIS_DIR/lib/utils.sh"

# Bids: bidder1 (815) wins; bidders 2 (402) and 3 (382) are a 2% gap of
# the 1000 bound — the sign map must binarize it, not leak it.
BIDS=(220.5 815.0 402.0 382.0)
BID_BOUND=1000
SIGN_ITERATIONS=12

# The ceremony plan is a deterministic function of ParamSet 2 (HYBRID: one
# key for all 24 sign-map levels, see
# e3_fhe_params::ckks_presets::relin_ceremony_plan_for_param_set). The
# joint key lands under each COMMITTEE node's data dir (every committee
# node writes byte-identical bytes); sortition picks 3 of the 5 nodes, so
# the poll below looks under ALL node dirs and uses the first copy found.
# CKKS_RELIN_KEY_DIR remains an optional override for tooling.
EXPECTED_KEYS=1
if [ -n "${CKKS_RELIN_KEY_DIR:-}" ]; then
  RLK_GLOB="$CKKS_RELIN_KEY_DIR"
else
  RLK_GLOB="$SCRIPT_DIR/.interfold/data/cn*/ckks/relin-keys"
fi

# Fresh node state: the per-run event logs/snapshots under .interfold/data
# grow multi-GB per ceremony run and stale state from a previous chain
# breaks recovery. (A full disk here surfaced as 'Snapshot batch flush
# failed: No space left on device' + silent RelinCeremonyShare loss.)
rm -rf "$SCRIPT_DIR/.interfold/data"

heading "Start the EVM node"

launch_evm

until curl -sf -X POST http://localhost:8545 -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' > /dev/null; do
  sleep 1
done

pnpm evm:clean

heading "Deploy contracts (mock verifiers; registers CKKS E3 program + ParamSet 2)"
pnpm evm:deploy

heading "Sync tests/integration/interfold.config.yaml from deployed_contracts.json"
(cd "$ROOT_DIR/packages/interfold-contracts" && pnpm utils:sync-integration-config)

CKKS_PROGRAM_ADDRESS=$(python3 -c "
import json
d = json.load(open('$ROOT_DIR/packages/interfold-contracts/deployed_contracts.json'))
print(d['localhost']['MockCkksE3Program']['address'])
")
echo "CKKS E3 program (program address => protocol): $CKKS_PROGRAM_ADDRESS"

interfold_wallet_set cn1 "$PRIVATE_KEY_CN1"
interfold_wallet_set cn2 "$PRIVATE_KEY_CN2"
interfold_wallet_set cn3 "$PRIVATE_KEY_CN3"
interfold_wallet_set cn4 "$PRIVATE_KEY_CN4"
interfold_wallet_set cn5 "$PRIVATE_KEY_CN5"

heading "Setup ZK prover"
$INTERFOLD_BIN noir setup

# start swarm
interfold_nodes_up

echo "waiting on binaries and utilities..."
# Tool binaries: default to the debug build; CKKS_TOOLS_PROFILE=release
# switches to the release build (the node binary is chosen separately via
# INTERFOLD_BIN — pass target/release/interfold there for ceremony speed).
TOOLS_DIR="$ROOT_DIR/target/${CKKS_TOOLS_PROFILE:-debug}"
waiton-files "$TOOLS_DIR/ckks_encrypt" "$TOOLS_DIR/ckks_auction_eval" "$TOOLS_DIR/pack_ckks_params"

sleep 4

for addr in "$CIPHERNODE_ADDRESS_1" "$CIPHERNODE_ADDRESS_2" "$CIPHERNODE_ADDRESS_3" "$CIPHERNODE_ADDRESS_4" "$CIPHERNODE_ADDRESS_5"; do
  heading "Add ciphernode $addr"
  pnpm ciphernode:add --ciphernode-address "$addr" --network localhost
done

heading "Request Committee through the CKKS program (ParamSet 2: sign-extraction ladder)"

CURRENT_TIMESTAMP=$(get_evm_timestamp)
INPUT_WINDOW_START=$((CURRENT_TIMESTAMP + 20))
INPUT_WINDOW_END=$((CURRENT_TIMESTAMP + 30))

REQUEST_OUTPUT=$(pnpm committee:new \
  --network localhost \
  --input-window-start "$INPUT_WINDOW_START" \
  --input-window-end "$INPUT_WINDOW_END" \
  --e3-address "$CKKS_PROGRAM_ADDRESS" \
  --committee-size 0 \
  --param-set 2)
printf '%s\n' "$REQUEST_OUTPUT"

E3_ID=$(extract_e3_id "$REQUEST_OUTPUT")
echo "E3 id: $E3_ID"

heading "Wait for the committee's aggregated CKKS public key (real DKG over WIDE transport)"
wait_for_committee_pubkey "$E3_ID" "$SCRIPT_DIR/output/ckks_pubkey.bin" "$INTEGRATION_DKG_TIMEOUT"

heading "Wait for the hybrid relin ceremony's joint key ($RLK_GLOB/31337:$E3_ID)"
# Key-count poll. PITFALL (cost two live runs): under `set -euo pipefail`,
# `ls <no-match> | wc -l` FAILS the pipeline (ls exit 2 + pipefail) and the
# failing assignment aborts the whole script on the FIRST poll — before the
# ceremony has produced anything. `find` exits 0 on an empty result.
# The glob may match several committee dirs: count the FIRST one found.
find_key() { { find $RLK_GLOB/31337:"$E3_ID" -name 'rlk_hybrid.bin' 2>/dev/null || true; } | head -n 1; }
count_keys() { { find_key; } | wc -l | tr -d ' '; }
for _ in $(seq 1 120); do
  COUNT=$(count_keys)
  if [ "$COUNT" -ge "$EXPECTED_KEYS" ]; then
    break
  fi
  sleep 2
done
COUNT=$(count_keys)
if [ "$COUNT" -lt "$EXPECTED_KEYS" ]; then
  echo "relin ceremony incomplete: $COUNT/$EXPECTED_KEYS keys under $RLK_GLOB/31337:$E3_ID"
  echo "Test FAILED"
  exit 1
fi
RLK_DIR="$(dirname "$(find_key)")"
echo "ceremony complete: $COUNT joint hybrid key in $RLK_DIR ($(wc -c < "$RLK_DIR/rlk_hybrid.bin" | tr -d ' ') bytes)"

heading "Encrypt REAL bids under the committee public key (ladder params)"
CKKS_PARAMS=$($TOOLS_DIR/pack_ckks_params --param-set 2)

BID_FILES=""
for i in "${!BIDS[@]}"; do
  $TOOLS_DIR/ckks_encrypt \
    --pubkey "$SCRIPT_DIR/output/ckks_pubkey.bin" \
    --params "$CKKS_PARAMS" \
    --value "${BIDS[$i]}" \
    --output "$SCRIPT_DIR/output/bid_$i.bin"
  BID_FILES="${BID_FILES:+$BID_FILES,}$SCRIPT_DIR/output/bid_$i.bin"
done

heading "Evaluate the auction: ITERATED SIGN EXTRACTION (winner mode)"
$TOOLS_DIR/ckks_auction_eval \
  --params "$CKKS_PARAMS" \
  --bids "$BID_FILES" \
  --output "$SCRIPT_DIR/output/auction_round.bin" \
  --commitment-output "$SCRIPT_DIR/output/auction_commitment.bin" \
  --mode winner \
  --rlk-dir "$RLK_DIR" \
  --bound "$BID_BOUND" \
  --iterations "$SIGN_ITERATIONS"

heading "Mock publish input e3-id"
pnpm e3-program:publishInput --network localhost --e3-id "$E3_ID" --data 0x12345678

sleep 4

heading "Publish the evaluated auction ciphertext to the EVM"
pnpm e3:publishCiphertext --e3-id "$E3_ID" --network localhost \
  --data-file "$SCRIPT_DIR/output/auction_round.bin" \
  --ciphertext-commitment-file "$SCRIPT_DIR/output/auction_commitment.bin" \
  --proof 0x12345678

heading "Wait for the committee's threshold decryption on-chain"
wait_for_plaintext_output "$E3_ID" "$SCRIPT_DIR/output/ckks_plaintext_raw.txt"

heading "Decode the CKKS fixed-point plaintext"
pnpm --dir "$ROOT_DIR/packages/interfold-contracts" e3:get-ckks-plaintext \
  --network localhost --e3-id "$E3_ID" \
  --out-file "$SCRIPT_DIR/output/ckks_plaintext.txt"

ACTUAL=$(cat "$SCRIPT_DIR/output/ckks_plaintext.txt")
echo "Decrypted winner-mode output: $ACTUAL"

# All i<j pairs of 4 bidders, packed in slot order:
# (0,1)(0,2)(0,3)(1,2)(1,3)(2,3). Every slot must be the CORRECT sign AND
# saturated at ±1 (|slot| in [0.95, 1.05]) — including the 2% gap pair
# (2,3): winner mode leaks the comparison bits and NOTHING else.
SIGN_CHECK=$(python3 -c "
bids = [${BIDS[0]}, ${BIDS[1]}, ${BIDS[2]}, ${BIDS[3]}]
values = [float(v) for v in '''$ACTUAL'''.split(',')]
pairs = [(i, j) for i in range(len(bids)) for j in range(i + 1, len(bids))]
errors = []
for p, (a, b) in enumerate(pairs):
    v = values[p]
    if (v > 0) != (bids[a] > bids[b]):
        errors.append(f'pair {p} ({a},{b}): wrong sign {v}')
    if abs(abs(v) - 1.0) > 0.05:
        errors.append(f'pair {p} ({a},{b}): NOT binarized {v} (magnitude leak)')
wins = [0] * len(bids)
for p, (a, b) in enumerate(pairs):
    wins[a if values[p] > 0 else b] += 1
champion = max(range(len(bids)), key=lambda i: wins[i])
if champion != 1:
    errors.append(f'wrong winner: bidder {champion}')
print('PASS' if not errors else 'FAIL: ' + '; '.join(errors))
")
echo "Winner-mode check: $SIGN_CHECK"

if [[ "$SIGN_CHECK" != "PASS" ]]; then
  echo "CKKS winner-mode auction produced wrong output"
  echo "Test FAILED"
  exit 1
fi

heading "CKKS winner-mode auction e2e PASSED !"
echo "Winner: bidder 1. Opened output contained ONLY saturated ±1 signs (2% gap pair included)."

gracefull_shutdown
