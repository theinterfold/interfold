#!/usr/bin/env bash
# The v2 nodes end to end on a local chain, with placeholder proofs that mock verifiers accept:
# five operators, one Minimum committee that selects itself, runs its DKG, publishes its key, and
# decrypts a ciphertext that it fetches from the mock availability layer. Each node is its own
# process; the nodes find each other through the first one.
#
# With V2_RESTART=true it kills the decryption aggregator once the key is out and starts it again
# from its journal and blob store before the ciphertext arrives.
#
# With V2_NOIR_DIR set to a directory that holds `bin/bb` and the compiled `circuits`, the nodes
# make real proofs and the contracts verify them.
#
# With V2_CLI=true the operators run their nodes as operators do: `interfold wallet set` stores
# each key, and `interfold nodes up` runs `interfold start` for every node of one configuration
# file, beside a bootstrap node. The restart is then `interfold nodes restart`, which stops the node
# with SIGTERM.
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
NOIR_DIR="${V2_NOIR_DIR:-}"
TIMEOUT="${V2_TIMEOUT:-$([[ -n "$NOIR_DIR" ]] && echo 3600 || echo 900)}"
CLI="${V2_CLI:-false}"
INTERFOLD="$ROOT_DIR/target/debug/interfold"
CONFIG="$OUT/cli/interfold.config.yaml"
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
# Last started first, so the nodes stop before the chain they read.
stop() {
  local index
  for ((index = ${#STARTED[@]} - 1; index >= 0; index--)); do
    kill "${STARTED[index]}" 2>/dev/null || true
    wait "${STARTED[index]}" 2>/dev/null || true
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

heading "Build the v2 node and the requester's encryption tool"
if [[ "$CLI" == "true" ]]; then
  # Without the feature the CLI refuses a configuration that skips proofs.
  (cd "$ROOT_DIR" && cargo build --bin interfold --features e3-cli/test-only-skip-proof-aggregation)
else
  (cd "$ROOT_DIR" && cargo build --bin e3-node)
fi
(cd "$ROOT_DIR" && cargo build -p e3-tests --bin fake_encrypt)

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

if [[ -n "$NOIR_DIR" ]]; then
  heading "Deploy the contracts with the circuit verifiers"
  (cd "$ROOT_DIR" && pnpm evm:clean && ENABLE_ZK_VERIFICATION=true pnpm evm:deploy)
else
  heading "Deploy the contracts with mock verifiers"
  (cd "$ROOT_DIR" && pnpm evm:clean && pnpm evm:deploy)
fi

heading "Register the operators"
for address in "${ADDRESSES[@]}"; do
  (cd "$ROOT_DIR" && pnpm ciphernode:add --ciphernode-address "$address" --network localhost)
done

heading "Start the v2 nodes"
NODE_PIDS=()
# Node `index` listens on its own port and dials `peer`, if any.
start_node() {
  local index="$1" peer="$2"
  local dir="$OUT/nodes/node-$index"
  mkdir -p "$dir"
  jq -n \
    --arg interfold "$(jq -r '.localhost.Interfold.address' "$DEPLOYED")" \
    --arg registry "$(jq -r '.localhost.CiphernodeRegistryOwnable.address' "$DEPLOYED")" \
    --arg bonding "$(jq -r '.localhost.BondingRegistry.address' "$DEPLOYED")" \
    --arg data_dir "$dir" \
    --arg operator "${KEYS[$index]}" \
    --arg identity "$(printf '0x%064x' $((index + 1)))" \
    --arg listen "/ip4/127.0.0.1/udp/$((9400 + index))/quic-v1" \
    --arg peer "$peer" \
    --arg noir "$NOIR_DIR" \
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
      operator: $operator,
      cipher_password: "v2 end to end",
      network: {
        id: "localhost",
        identity: $identity,
        listen: [$listen],
        peers: (if $peer == "" then [] else [$peer] end)
      }
    } + (if $noir == "" then {} else {noir_dir: $noir} end)' >"$dir/config.json"
  RUST_LOG="${RUST_LOG:-info,e3_node=debug}" "$ROOT_DIR/target/debug/e3-node" "$dir/config.json" \
    >"$dir/node.log" 2>&1 &
  STARTED+=($!)
  NODE_PIDS[$index]=$!
}
# The operators' configuration for the CLI, with node `cnN` for operator N - 1, and a bootstrap
# node with a wallet of its own. `nodes up` gives every node the others as peers.
write_cli_config() {
  local skip=true
  [[ -n "$NOIR_DIR" ]] && skip=false
  cat <<EOF
chains:
  - name: localhost
    rpc_url: ws://127.0.0.1:8545
    ingestion_confirmations: 0
    rpc_poll_interval_ms: 250
    data_availability:
      mode: mock_http
      rpc_url: http://127.0.0.1:4000/availability
    contracts:
      interfold:
        address: "$(jq -r '.localhost.Interfold.address' "$DEPLOYED")"
        deploy_block: 0
      ciphernode_registry:
        address: "$(jq -r '.localhost.CiphernodeRegistryOwnable.address' "$DEPLOYED")"
        deploy_block: 0
      bonding_registry:
        address: "$(jq -r '.localhost.BondingRegistry.address' "$DEPLOYED")"
        deploy_block: 0
nodes:
EOF
  for index in "${!ADDRESSES[@]}"; do
    cat <<EOF
  cn$((index + 1)):
    address: "${ADDRESSES[$index]}"
    quic_port: $((9400 + index))
    ctrl_port: $((50610 + index))
    autonetkey: true
    autopassword: true
    skip_proof_aggregation: $skip
EOF
  done
  cat <<EOF
  boot:
    quic_port: 9405
    ctrl_port: 50615
    autopassword: true
    autowallet: true
    bootstrap: true
EOF
}
nodes_running() {
  if [[ "$CLI" == "true" ]]; then
    for name in boot $(seq -f 'cn%g' 1 "${#ADDRESSES[@]}"); do
      pgrep -f "start --name $name (--bootstrap )?--config $CONFIG" >/dev/null
    done
  else
    for pid in "${NODE_PIDS[@]}"; do
      kill -0 "$pid"
    done
  fi
}
if [[ "$CLI" == "true" ]]; then
  # The CLI finds the circuits and bb in the `.interfold` folder beside its configuration.
  mkdir -p "$OUT/cli/.interfold"
  [[ -n "$NOIR_DIR" ]] && ln -s "$NOIR_DIR" "$OUT/cli/.interfold/noir"
  write_cli_config >"$CONFIG"
  for index in "${!KEYS[@]}"; do
    printf '%s\n' "${KEYS[$index]}" | "$INTERFOLD" wallet set --name "cn$((index + 1))" \
      --config "$CONFIG" --private-key-stdin
  done
  "$INTERFOLD" nodes up -v --config "$CONFIG" >"$OUT/cli/nodes.log" 2>&1 &
  STARTED+=($!)
else
  start_node 0 ""
  until_ok 120 test -s "$OUT/nodes/node-0/listening"
  FIRST=$(head -n 1 "$OUT/nodes/node-0/listening")
  for index in 1 2 3 4; do
    start_node "$index" "$FIRST"
  done
fi

heading "Wait until every operator acknowledged the release and is active"
BONDING="$(jq -r '.localhost.BondingRegistry.address' "$DEPLOYED")"
operator_active() {
  [[ "$(cast call "$BONDING" "isActive(address)(bool)" "$1" --rpc-url http://127.0.0.1:8545)" == "true" ]]
}
for address in "${ADDRESSES[@]}"; do
  until_ok 180 operator_active "$address"
done
nodes_running

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
nodes_running
advance_evm_time_past "$INPUT_WINDOW_START"

if [[ "${V2_RESTART:-false}" == "true" ]]; then
  heading "Kill the decryption aggregator and start it again"
  REGISTRY="$(jq -r '.localhost.CiphernodeRegistryOwnable.address' "$DEPLOYED")"
  # The committee in address order; its first member aggregates the plaintext.
  AGGREGATOR=$(cast call "$REGISTRY" "getActiveCommitteeNodes(uint256)(address[],uint256[])" \
    "$E3_ID" --rpc-url http://127.0.0.1:8545 | head -n 1 | tr -d '[] ' | cut -d',' -f1)
  for index in "${!ADDRESSES[@]}"; do
    if [[ "${ADDRESSES[$index],,}" == "${AGGREGATOR,,}" ]]; then
      echo "The aggregator $AGGREGATOR is node $index"
      if [[ "$CLI" == "true" ]]; then
        "$INTERFOLD" nodes restart "cn$((index + 1))" --config "$CONFIG"
      else
        kill -9 "${NODE_PIDS[$index]}"
        sleep 5
        peer="$FIRST"
        [[ "$index" == 0 ]] && peer=""
        start_node "$index" "$peer"
      fi
    fi
  done
  [[ "$CLI" == "true" ]] || until_ok 60 test -s "$OUT/nodes/node-0/listening"
fi

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

heading "Wait for every node to delete the E3's blobs"
no_blobs() {
  local blobs checked=0
  for blobs in "$OUT"/nodes/node-*/blobs "$OUT"/cli/.interfold/data/*/v2/blobs; do
    [[ -d "$blobs" ]] || continue
    [[ -z "$(ls -A "$blobs")" ]] || return 1
    checked=$((checked + 1))
  done
  ((checked == ${#ADDRESSES[@]}))
}
until_ok 120 no_blobs
heading "PASSED"
