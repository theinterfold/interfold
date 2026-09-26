#!/usr/bin/env bash

# Upgrade compatibility test.
#
# DKG runs on the released binary. Committee members then stop and restart on the candidate
# binary with the same config and data. The E3 must still produce the correct plaintext, the
# candidate must accept the released node's persisted state, and the restart must not lose it.
#
# Required:
#   INTERFOLD_BIN_OLD  released binary, for example v0.18.0
#   INTERFOLD_BIN_NEW  candidate binary
# Build both with the same Cargo features as the chosen test profile (see test.sh).
#
# UPGRADE_SCENARIO:
#   all       every node moves to the candidate after DKG (default)
#   mixed     every committee member except the active aggregator moves to the candidate after
#             DKG. Only the honest roster may send decryption shares, and the minimum committee's
#             roster has two members, so the released aggregator must verify at least one
#             candidate share.
#   late      every node stops before the ciphertext is published and restarts on the candidate
#             after it, so the candidate must catch up from chain history and then decrypt
#   rollback  every node moves to the candidate after DKG, then back to the released binary,
#             which must load the candidate's state and decrypt
#   mixed-dkg cn2 and cn4 run the candidate from the start and the other nodes the released
#             binary, so DKG and decryption both run across versions, as for an E3 requested during
#             the rollout. The run fails as inconclusive when the committee is not mixed.
#
# Run from tests/integration:
#   INTERFOLD_BIN_OLD=... INTERFOLD_BIN_NEW=... UPGRADE_SCENARIO=mixed ./test.sh upgrade

set -eu

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

: "${INTERFOLD_BIN_OLD:?set INTERFOLD_BIN_OLD to the released interfold binary}"
: "${INTERFOLD_BIN_NEW:?set INTERFOLD_BIN_NEW to the candidate interfold binary}"
UPGRADE_SCENARIO="${UPGRADE_SCENARIO:-all}"
case "$UPGRADE_SCENARIO" in
  all|mixed|late|rollback|mixed-dkg) ;;
  *) echo "Unknown UPGRADE_SCENARIO: $UPGRADE_SCENARIO (use all, mixed, late, rollback, or mixed-dkg)" >&2; exit 1 ;;
esac

export INTERFOLD_BIN="$INTERFOLD_BIN_OLD"
source "$THIS_DIR/fns.sh"
source "$THIS_DIR/lib/utils.sh"

CONFIG="$SCRIPT_DIR/interfold.config.yaml"
INVENTORY="$SCRIPT_DIR/lib/state_inventory.py"
ALL_NODES="cn1 cn2 cn3 cn4 cn5"
# Nodes that run the candidate from the start in the mixed-dkg scenario.
MIXED_DKG_NEW="cn2 cn4"

# Start one node on the given binary with the other nodes as peers, as `interfold nodes up`
# does. Each binary writes its own log so the checks below can inspect the candidate alone.
start_node() {
  local bin="$1" name="$2" label="$3" other port peers=()
  for other in $ALL_NODES; do
    [[ "$other" == "$name" ]] && continue
    port=$("$INTERFOLD_BIN_OLD" config get quic_port --name "$other" --config "$CONFIG")
    peers+=(--peer "/ip4/127.0.0.1/udp/$port/quic-v1")
  done
  heading "Start $name on the $label binary"
  "$bin" start -v --name "$name" --config "$CONFIG" "${peers[@]}" \
    >>"$SCRIPT_DIR/output/$name.$label.log" 2>&1 &
  echo "$!" >"$SCRIPT_DIR/output/$name.pid"
}

# Send SIGTERM and wait for the graceful shutdown to finish.
stop_node() {
  local name="$1" pid waited=0
  pid=$(cat "$SCRIPT_DIR/output/$name.pid")
  heading "Stop $name (pid $pid)"
  kill -TERM "$pid" 2>/dev/null || true
  while kill -0 "$pid" 2>/dev/null; do
    if ((waited >= 180)); then
      echo "$name did not stop within 180 s" >&2
      return 1
    fi
    sleep 1
    waited=$((waited + 1))
  done
  wait "$pid" 2>/dev/null || true
}

# Wait until a node has replayed its state, joined the network, and enabled effects. A restart can
# take about a minute while the node finishes its first peer dials.
wait_for_effects() {
  local name="$1" label="$2" waited=0
  until grep -q "Effects enabled." "$SCRIPT_DIR/output/$name.$label.log" 2>/dev/null; do
    if ((waited >= 300)); then
      echo "$name did not enable effects on the $label binary within 300 s" >&2
      return 1
    fi
    sleep 2
    waited=$((waited + 2))
  done
}

node_state_dirs() {
  echo "$SCRIPT_DIR/.interfold/data/$1" "$SCRIPT_DIR/.interfold/config/$1"
}

# Stop a node and prove that the binary it restarts on accepts its state. The first stop records
# the inventory that the final check compares against.
prepare_switch() {
  local name="$1" bin="$2" label="$3"
  stop_node "$name"
  if [[ ! -f "$SCRIPT_DIR/output/$name.before.json" ]]; then
    # shellcheck disable=SC2046
    python3 "$INVENTORY" snapshot "$SCRIPT_DIR/output/$name.before.json" $(node_state_dirs "$name")
  fi
  heading "Validate $name state with the $label binary"
  "$bin" node validate --name "$name" --config "$CONFIG" \
    | tee "$SCRIPT_DIR/output/$name.$label.validate.txt"
  if ! grep -q "VALIDATION PASSED" "$SCRIPT_DIR/output/$name.$label.validate.txt"; then
    echo "The $label binary rejected the state of $name" >&2
    return 1
  fi
}

registry_address() {
  grep -A1 "ciphernode_registry:" "$CONFIG" | sed -n 's/.*address: *"\{0,1\}\(0x[0-9a-fA-F]*\)"\{0,1\}.*/\1/p' | head -n 1
}

committee_node_names() {
  local e3_id="$1" addresses address
  addresses=$(cast call "$(registry_address)" "getCommitteeNodes(uint256)(address[])" "$e3_id" \
    --rpc-url http://localhost:8545 | tr -d '[] ' | tr ',' ' ')
  for address in $addresses; do
    node_name_for_address "$address"
  done
}

heading "Start the EVM node"

launch_evm
launch_mock_data_availability

until curl -sf -X POST http://localhost:8545 -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' > /dev/null; do
  sleep 1
done

pnpm evm:clean

if [[ "$FULL_PROOF_AGGREGATION" == "true" ]]; then
  ENABLE_ZK_VERIFICATION=true pnpm evm:deploy
else
  pnpm evm:deploy
fi

(cd "$ROOT_DIR/packages/interfold-contracts" && pnpm utils:sync-integration-config)

interfold_wallet_set cn1 "$PRIVATE_KEY_CN1"
interfold_wallet_set cn2 "$PRIVATE_KEY_CN2"
interfold_wallet_set cn3 "$PRIVATE_KEY_CN3"
interfold_wallet_set cn4 "$PRIVATE_KEY_CN4"
interfold_wallet_set cn5 "$PRIVATE_KEY_CN5"

heading "Setup ZK prover"
$INTERFOLD_BIN noir setup

for name in $ALL_NODES; do
  if [[ "$UPGRADE_SCENARIO" == "mixed-dkg" && " $MIXED_DKG_NEW " == *" $name "* ]]; then
    start_node "$INTERFOLD_BIN_NEW" "$name" new
  else
    start_node "$INTERFOLD_BIN_OLD" "$name" old
  fi
done

waiton-files "$ROOT_DIR/target/debug/fake_encrypt"

pnpm ciphernode:add --ciphernode-address "$CIPHERNODE_ADDRESS_1" --network localhost
pnpm ciphernode:add --ciphernode-address "$CIPHERNODE_ADDRESS_2" --network localhost
pnpm ciphernode:add --ciphernode-address "$CIPHERNODE_ADDRESS_3" --network localhost
pnpm ciphernode:add --ciphernode-address "$CIPHERNODE_ADDRESS_4" --network localhost
pnpm ciphernode:add --ciphernode-address "$CIPHERNODE_ADDRESS_5" --network localhost

heading "Request Committee"

ENCODED_PARAMS=0x$("$SCRIPT_DIR/lib/pack_e3_params.sh" \
  --moduli 0xffffee001 \
  --moduli 0xffffc4001 \
  --degree 512 \
  --plaintext-modulus 100)

set_integration_input_window

REQUEST_OUTPUT=$(pnpm committee:new \
  --network localhost \
  --input-window-start "$INPUT_WINDOW_START" \
  --input-window-end "$INPUT_WINDOW_END" \
  --e3-params "$ENCODED_PARAMS" \
  --committee-size 0)
printf '%s\n' "$REQUEST_OUTPUT"

E3_ID=$(extract_e3_id "$REQUEST_OUTPUT")

wait_for_committee_pubkey "$E3_ID" "$SCRIPT_DIR/output/pubkey.bin" "${INTEGRATION_DKG_TIMEOUT:-1300}"
advance_evm_time_past "$INPUT_WINDOW_START"

COMMITTEE=$(committee_node_names "$E3_ID" | tr '\n' ' ')
ACTIVE_AGG=$(node_name_for_address "$(wait_for_active_aggregator_address "$E3_ID")")
echo "Committee: $COMMITTEE; active aggregator: $ACTIVE_AGG"

UPGRADED=""
case "$UPGRADE_SCENARIO" in
  all|late|rollback)
    UPGRADED="$ALL_NODES"
    ;;
  mixed)
    for name in $COMMITTEE; do
      [[ "$name" != "$ACTIVE_AGG" ]] && UPGRADED="$UPGRADED $name"
    done
    ;;
  mixed-dkg)
    committee_new=0
    committee_old=0
    for name in $COMMITTEE; do
      if [[ " $MIXED_DKG_NEW " == *" $name "* ]]; then
        committee_new=$((committee_new + 1))
      else
        committee_old=$((committee_old + 1))
      fi
    done
    if ((committee_new == 0 || committee_old == 0)); then
      echo "Inconclusive: committee [$COMMITTEE] does not mix the binaries; run the scenario again" >&2
      echo "Test FAILED"
      exit 1
    fi
    ;;
esac
echo "Scenario $UPGRADE_SCENARIO: move [$UPGRADED ] to the candidate"

for name in $UPGRADED; do
  prepare_switch "$name" "$INTERFOLD_BIN_NEW" new
  if [[ "$UPGRADE_SCENARIO" != "late" ]]; then
    start_node "$INTERFOLD_BIN_NEW" "$name" new
  fi
done

if [[ "$UPGRADE_SCENARIO" == "rollback" ]]; then
  # Let the candidate write state before the rollback.
  sleep 30
  for name in $UPGRADED; do
    prepare_switch "$name" "$INTERFOLD_BIN_OLD" rollback
    start_node "$INTERFOLD_BIN_OLD" "$name" rollback
  done
fi

# Wait until every restarted node takes part again before the ciphertext arrives. In the late
# scenario the nodes start only after the ciphertext.
if [[ "$UPGRADE_SCENARIO" != "late" ]]; then
  WAIT_LABEL=new
  [[ "$UPGRADE_SCENARIO" == "rollback" ]] && WAIT_LABEL=rollback
  for name in $UPGRADED; do
    wait_for_effects "$name" "$WAIT_LABEL"
  done
fi

heading "Mock encrypted plaintext"
"$SCRIPT_DIR/lib/fake_encrypt.sh" --input "$SCRIPT_DIR/output/pubkey.bin" --output "$SCRIPT_DIR/output/output.bin" --commitment-output "$SCRIPT_DIR/output/ciphertext_commitment.bin" --plaintext "$PLAINTEXT" --params "$ENCODED_PARAMS"

heading "Mock publish input e3-id"
pnpm e3-program:publishInput --network localhost --e3-id "$E3_ID" --data 0x12345678

advance_evm_time_past "$INPUT_WINDOW_END"

waiton "$SCRIPT_DIR/output/output.bin"

heading "Publish ciphertext to EVM"
pnpm e3:publishCiphertext \
  --e3-id "$E3_ID" \
  --network localhost \
  --data-file "$SCRIPT_DIR/output/output.bin" \
  --ciphertext-commitment-file "$SCRIPT_DIR/output/ciphertext_commitment.bin" \
  --proof 0x12345678 \
  --mock-data-availability-directory "$MOCK_DATA_AVAILABILITY_DIRECTORY"

if [[ "$UPGRADE_SCENARIO" == "late" ]]; then
  for name in $UPGRADED; do
    start_node "$INTERFOLD_BIN_NEW" "$name" new
  done
fi

wait_for_plaintext_output "$E3_ID" "$SCRIPT_DIR/output/plaintext.txt"

ACTUAL=$(cut -d',' -f1,2 "$SCRIPT_DIR/output/plaintext.txt")
if [[ "$ACTUAL" != "$PLAINTEXT"* ]]; then
  echo "Invalid plaintext decrypted: actual='$ACTUAL' expected='$PLAINTEXT'"
  echo "Test FAILED"
  exit 1
fi

heading "Check candidate-node logs and persisted state"
FAILED=0
LAST_LABEL=new
[[ "$UPGRADE_SCENARIO" == "rollback" ]] && LAST_LABEL=rollback
CANDIDATE_NODES="$UPGRADED"
[[ "$UPGRADE_SCENARIO" == "mixed-dkg" ]] && CANDIDATE_NODES="$MIXED_DKG_NEW"
SHARES_SENT=0
for name in $CANDIDATE_NODES; do
  if ! wait_for_effects "$name" "$LAST_LABEL"; then
    FAILED=1
  fi
  for label in new $LAST_LABEL; do
    if grep -E -n "Halting|panicked at|Failed to deserialize|failed to decode" \
      "$SCRIPT_DIR/output/$name.$label.log"; then
      echo "$name: the $label log shows a load or decode failure" >&2
      FAILED=1
    fi
  done
  # Every committee member creates a decryption share; the aggregator uses only the roster's.
  if [[ " $COMMITTEE " == *" $name "* ]]; then
    if grep -q "Decryption share sending process is complete" "$SCRIPT_DIR/output/$name.$LAST_LABEL.log"; then
      SHARES_SENT=$((SHARES_SENT + 1))
    elif [[ "$UPGRADE_SCENARIO" != "late" ]]; then
      # The node was up before the ciphertext arrived, so it must have sent its share.
      echo "$name: no decryption share after the switch" >&2
      FAILED=1
    fi
  fi
done
# In the late scenario the round can end before a slow node sends its share, so at least one
# candidate committee member must have sent one.
if ((SHARES_SENT == 0)); then
  echo "no candidate committee member sent a decryption share" >&2
  FAILED=1
fi

for name in $ALL_NODES; do
  stop_node "$name"
done
for name in $UPGRADED; do
  # shellcheck disable=SC2046
  python3 "$INVENTORY" snapshot "$SCRIPT_DIR/output/$name.after.json" \
    --baseline "$SCRIPT_DIR/output/$name.before.json" $(node_state_dirs "$name")
  echo "$name:"
  python3 "$INVENTORY" compare "$SCRIPT_DIR/output/$name.before.json" "$SCRIPT_DIR/output/$name.after.json" || FAILED=1
done

kill_em_all

if [[ "$FAILED" != "0" ]]; then
  echo "Test FAILED"
  exit 1
fi

heading "Test PASSED ! ($UPGRADE_SCENARIO)"
