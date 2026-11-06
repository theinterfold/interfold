#!/usr/bin/env bash
# The v2 nodes end to end on a local chain with mock verifiers: five operators, one Minimum
# committee that selects itself, runs its DKG, publishes its key, and decrypts a ciphertext that
# it fetches from the mock availability layer. The nodes run in one process on an in-memory network.
#
# Run from the repository root. It starts anvil on 8545 and the availability server on 4000, and
# stops only the processes it started.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUT="$SCRIPT_DIR/output/v2"
AVAILABILITY_DIR="$OUT/data-availability"
DEPLOYED="$ROOT_DIR/packages/interfold-contracts/deployed_contracts.json"
PLAINTEXT="4,0"
TIMEOUT="${V2_TIMEOUT:-900}"
# The committee cannot publish its key after the input window closes; it must outlast the DKG.
INTEGRATION_DKG_TIMEOUT="$TIMEOUT"

source "$SCRIPT_DIR/lib/utils.sh"

KEYS=(
  0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
  0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
  0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6
  0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a
  0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba
)
ADDRESSES=(
  0x70997970C51812dc3A010C7d01b50e0d17dc79C8
  0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC
  0x90F79bf6EB2c4f870365E785982E1f101E93b906
  0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65
  0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc
)

STARTED=()
stop() {
  for pid in "${STARTED[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
}
trap stop EXIT

heading() {
  echo
  echo "== $*"
}

# Runs a command until it succeeds or `seconds` pass.
until_ok() {
  local seconds="$1"
  shift
  local deadline=$((SECONDS + seconds))
  until "$@" >/dev/null 2>&1; do
    if ((SECONDS >= deadline)); then
      echo "Gave up after ${seconds}s: $*" >&2
      return 1
    fi
    sleep 2
  done
}

rm -rf "$OUT"
mkdir -p "$AVAILABILITY_DIR"

heading "Build the v2 cluster and the requester's encryption tool"
(cd "$ROOT_DIR" && cargo build --bin e3-node-cluster && cargo build -p e3-tests --bin fake_encrypt)

heading "Start the chain and the availability layer"
anvil --host 127.0.0.1 --chain-id 31337 --block-time 1 \
  --mnemonic 'test test test test test test test test test test test junk' --silent &
STARTED+=($!)
DATA_AVAILABILITY_DIRECTORY="$AVAILABILITY_DIR" PORT=4000 \
  node "$SCRIPT_DIR/lib/mock-data-availability.mjs" >"$OUT/availability.log" 2>&1 &
STARTED+=($!)
until_ok 120 curl -sf -X POST http://127.0.0.1:8545 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
until_ok 60 curl -sf http://127.0.0.1:4000/health

heading "Deploy the contracts with mock verifiers"
(cd "$ROOT_DIR" && pnpm evm:clean && pnpm evm:deploy)

heading "Register the operators"
for address in "${ADDRESSES[@]}"; do
  (cd "$ROOT_DIR" && pnpm ciphernode:add --ciphernode-address "$address" --network localhost)
done

heading "Start the v2 nodes"
jq -n \
  --arg interfold "$(jq -r '.localhost.Interfold.address' "$DEPLOYED")" \
  --arg registry "$(jq -r '.localhost.CiphernodeRegistryOwnable.address' "$DEPLOYED")" \
  --arg bonding "$(jq -r '.localhost.BondingRegistry.address' "$DEPLOYED")" \
  --arg data_dir "$OUT/nodes" \
  --args \
  '{
    rpc_url: "http://127.0.0.1:8545",
    chain_id: 31337,
    interfold: $interfold,
    registry: $registry,
    bonding: $bonding,
    start_block: 0,
    confirmations: 0,
    poll_interval_ms: 250,
    availability_url: "http://127.0.0.1:4000/availability",
    data_dir: $data_dir,
    operators: $ARGS.positional
  }' "${KEYS[@]}" >"$OUT/cluster.json"
RUST_LOG="${RUST_LOG:-info,e3_node=debug}" "$ROOT_DIR/target/debug/e3-node-cluster" \
  "$OUT/cluster.json" >"$OUT/cluster.log" 2>&1 &
STARTED+=($!)
CLUSTER=$!

heading "Wait until every operator acknowledged the release and is active"
BONDING="$(jq -r '.localhost.BondingRegistry.address' "$DEPLOYED")"
operator_active() {
  [[ "$(cast call "$BONDING" "isActive(address)(bool)" "$1" --rpc-url http://127.0.0.1:8545)" == "true" ]]
}
for address in "${ADDRESSES[@]}"; do
  until_ok 180 operator_active "$address"
done
kill -0 "$CLUSTER"

heading "Request a committee"
set_integration_input_window
REQUEST_OUTPUT=$(cd "$ROOT_DIR" && pnpm committee:new \
  --network localhost \
  --input-window-start "$INPUT_WINDOW_START" \
  --input-window-end "$INPUT_WINDOW_END" \
  --committee-size 0 \
  --param-set 0)
printf '%s\n' "$REQUEST_OUTPUT"
E3_ID=$(extract_e3_id "$REQUEST_OUTPUT")

heading "Wait for the committee's key (E3 $E3_ID)"
(cd "$ROOT_DIR" && until_ok "$TIMEOUT" pnpm committee:get-public-key \
  --network localhost --e3-id "$E3_ID" --out-file "$OUT/pubkey.bin")
kill -0 "$CLUSTER"
advance_evm_time_past "$INPUT_WINDOW_START"

heading "Encrypt the plaintext and publish the ciphertext"
"$ROOT_DIR/target/debug/fake_encrypt" --input "$OUT/pubkey.bin" --output "$OUT/output.bin" \
  --commitment-output "$OUT/ciphertext_commitment.bin" --plaintext "$PLAINTEXT"
(cd "$ROOT_DIR" && pnpm e3-program:publishInput --network localhost --e3-id "$E3_ID" --data 0x12345678)
advance_evm_time_past "$INPUT_WINDOW_END"
(cd "$ROOT_DIR" && pnpm e3:publishCiphertext \
  --e3-id "$E3_ID" \
  --network localhost \
  --data-file "$OUT/output.bin" \
  --ciphertext-commitment-file "$OUT/ciphertext_commitment.bin" \
  --proof 0x12345678 \
  --mock-data-availability-directory "$AVAILABILITY_DIR")

heading "Wait for the plaintext"
(cd "$ROOT_DIR" && until_ok "$TIMEOUT" pnpm e3:get-plaintext \
  --network localhost --e3-id "$E3_ID" --out-file "$OUT/plaintext.txt")
ACTUAL=$(cut -d',' -f1,2 "$OUT/plaintext.txt")
echo "Decrypted: $ACTUAL"
if [[ "$ACTUAL" != "$PLAINTEXT"* ]]; then
  echo "FAILED: expected $PLAINTEXT" >&2
  exit 1
fi
heading "PASSED"
