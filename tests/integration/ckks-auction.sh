#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
#
# Full CKKS auction e2e: anvil + deployed contracts + REAL ciphernode
# processes + REAL encrypted bids.
#
#   1. Launch anvil, deploy contracts (mock verifiers) — the deploy
#      registers the CKKS E3 program (program address => protocol:
#      requesting through it binds keccak256("fhe.rs:CKKS")).
#   2. Boot the ciphernode swarm, register 5 ciphernodes.
#   3. Request a committee THROUGH THE CKKS PROGRAM (committee size +
#      paramSet only — the scheme follows from the program address).
#   4. Wait for the committee's aggregated CKKS public key (real DKG
#      across the node processes: EncryptionKeyPending → dealt shares →
#      KeyshareCreated → pk aggregation → on-chain publishCommittee).
#   5. Encrypt 4 REAL bids under the published pk (ckks_encrypt binary —
#      slot-replicated, fresh randomness; no fake_encrypt).
#   6. Evaluate the slot-batched auction round homomorphically
#      (ckks_auction_eval — masked pairwise differences; losing bids are
#      never decrypted) and publish the evaluated ciphertext on-chain.
#   7. Nodes threshold-decrypt; the aggregator publishes the canonical
#      fixed-point plaintext on-chain (publishPlaintextOutput).
#   8. Read it back via e3:getCkksPlaintext and check the masked signs
#      match the expected auction outcome.

set -eu

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

source "$THIS_DIR/fns.sh"
source "$THIS_DIR/lib/utils.sh"

# Bids: bidder2 (120.0) must beat bidder0/1/3.
BIDS=(50.0 80.0 120.0 30.0)

heading "Start the EVM node"

launch_evm

until curl -sf -X POST http://localhost:8545 -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' > /dev/null; do
  sleep 1
done

pnpm evm:clean

heading "Deploy contracts (mock verifiers; registers CKKS E3 program)"
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
waiton-files "$ROOT_DIR/target/debug/ckks_encrypt" "$ROOT_DIR/target/debug/ckks_auction_eval" "$ROOT_DIR/target/debug/pack_ckks_params"

sleep 4

for addr in "$CIPHERNODE_ADDRESS_1" "$CIPHERNODE_ADDRESS_2" "$CIPHERNODE_ADDRESS_3" "$CIPHERNODE_ADDRESS_4" "$CIPHERNODE_ADDRESS_5"; do
  heading "Add ciphernode $addr"
  pnpm ciphernode:add --ciphernode-address "$addr" --network localhost
done

heading "Request Committee through the CKKS program"

CURRENT_TIMESTAMP=$(get_evm_timestamp)
INPUT_WINDOW_START=$((CURRENT_TIMESTAMP + 20))
INPUT_WINDOW_END=$((CURRENT_TIMESTAMP + 30))

# Note: only committee size + input window + the PROGRAM ADDRESS — the
# scheme and params follow from the program (paramSet 0 => insecure-512
# CKKS preset on the node side).
REQUEST_OUTPUT=$(pnpm committee:new \
  --network localhost \
  --input-window-start "$INPUT_WINDOW_START" \
  --input-window-end "$INPUT_WINDOW_END" \
  --e3-address "$CKKS_PROGRAM_ADDRESS" \
  --committee-size 0)
printf '%s\n' "$REQUEST_OUTPUT"

E3_ID=$(extract_e3_id "$REQUEST_OUTPUT")
echo "E3 id: $E3_ID"

heading "Wait for the committee's aggregated CKKS public key (real DKG)"
wait_for_committee_pubkey "$E3_ID" "$SCRIPT_DIR/output/ckks_pubkey.bin" "$INTEGRATION_DKG_TIMEOUT"

heading "Encrypt REAL bids under the committee public key"
CKKS_PARAMS=$($ROOT_DIR/target/debug/pack_ckks_params \
  --moduli 0xffffee001,0xffffc4001 \
  --degree 512 \
  --scale-bits 26)

BID_FILES=""
for i in "${!BIDS[@]}"; do
  $ROOT_DIR/target/debug/ckks_encrypt \
    --pubkey "$SCRIPT_DIR/output/ckks_pubkey.bin" \
    --params "$CKKS_PARAMS" \
    --value "${BIDS[$i]}" \
    --output "$SCRIPT_DIR/output/bid_$i.bin"
  BID_FILES="${BID_FILES:+$BID_FILES,}$SCRIPT_DIR/output/bid_$i.bin"
done

heading "Evaluate the auction round homomorphically (losing bids never decrypted)"
$ROOT_DIR/target/debug/ckks_auction_eval \
  --params "$CKKS_PARAMS" \
  --bids "$BID_FILES" \
  --output "$SCRIPT_DIR/output/auction_round.bin" \
  --commitment-output "$SCRIPT_DIR/output/auction_commitment.bin"

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
echo "Decrypted masked round output: $ACTUAL"

# Round pairs are (0,1) and (2,3): masked signs of (bid0-bid1, bid2-bid3).
# Expected: slot0 < 0 (50 < 80), slot1 > 0 (120 > 30). Mask magnitudes are
# random, so only SIGNS are asserted. Slots beyond the pairs carry noise
# from the one-hot masks and are ignored.
SIGN_CHECK=$(python3 -c "
values = [float(v) for v in '''$ACTUAL'''.split(',')]
ok = values[0] < 0 and values[1] > 0
print('PASS' if ok else f'FAIL: {values[:2]}')
")
echo "Sign check: $SIGN_CHECK"

if [[ "$SIGN_CHECK" != "PASS" ]]; then
  echo "CKKS auction round produced wrong comparison signs"
  echo "Test FAILED"
  exit 1
fi

heading "CKKS auction e2e PASSED !"
echo "Winner bracket: bidder 1 beat bidder 0; bidder 2 beat bidder 3 (next round would pair them)."

gracefull_shutdown
