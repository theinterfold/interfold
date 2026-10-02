#!/usr/bin/env bash

# Upgrade compatibility test.
#
# DKG runs on the released binary. Committee members then stop and restart on the candidate
# binary with the same config and data. The E3 must still produce the correct plaintext, the
# candidate must accept the released node's persisted state, and the restart must not lose it.
#
# The in-place scenarios need a candidate with the same SCHEMA_VERSION as the released binary.
# Across a SCHEMA_VERSION raise, only `reset` with UPGRADE_RESET=all applies, and `mixed-dkg` when
# both binaries pin the same circuits version. The nodes share one circuits folder, and v0.17.0
# pins another version than later releases.
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
#   reset     a first E3 completes on the released binary. Its committee members then clear their
#             state with the candidate's `node reset-data`. The command keeps the operator key and
#             the libp2p keypair. The other nodes move to the candidate with their state. The reset
#             nodes must keep their identity. A second E3 must complete on the candidate, with a
#             reset node in its committee. With UPGRADE_RESET=all, every node resets. Use it when
#             the candidate raised SCHEMA_VERSION over the released binary, so that it cannot load
#             the released state, as for v0.17.0.
#
# Run from tests/integration:
#   INTERFOLD_BIN_OLD=... INTERFOLD_BIN_NEW=... UPGRADE_SCENARIO=mixed ./test.sh upgrade

set -eu

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

: "${INTERFOLD_BIN_OLD:?set INTERFOLD_BIN_OLD to the released interfold binary}"
: "${INTERFOLD_BIN_NEW:?set INTERFOLD_BIN_NEW to the candidate interfold binary}"
UPGRADE_SCENARIO="${UPGRADE_SCENARIO:-all}"
case "$UPGRADE_SCENARIO" in
  all|mixed|late|rollback|mixed-dkg|reset) ;;
  *) echo "Unknown UPGRADE_SCENARIO: $UPGRADE_SCENARIO (use all, mixed, late, rollback, mixed-dkg, or reset)" >&2; exit 1 ;;
esac
UPGRADE_RESET="${UPGRADE_RESET:-committee}"
case "$UPGRADE_RESET" in
  committee|all) ;;
  *) echo "Unknown UPGRADE_RESET: $UPGRADE_RESET (use committee or all)" >&2; exit 1 ;;
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

# Record the operator address and peer ID that the final check compares against.
record_identity() {
  local name="$1"
  if ! identity_of "$INTERFOLD_BIN_OLD" "$name" > "$SCRIPT_DIR/output/$name.identity.before"; then
    echo "Could not read the operator address and peer ID of $name before the switch" >&2
    return 1
  fi
}

# Prove that the binary a node restarts on accepts its state.
validate_state() {
  local name="$1" bin="$2" label="$3"
  heading "Validate $name state with the $label binary"
  "$bin" node validate --name "$name" --config "$CONFIG" \
    | tee "$SCRIPT_DIR/output/$name.$label.validate.txt"
  # A report with warnings ends with "VALIDATION PASSED WITH WARNINGS"; only a clean report passes.
  if ! grep -qF "VALIDATION PASSED —" "$SCRIPT_DIR/output/$name.$label.validate.txt"; then
    echo "The $label binary rejected the state of $name" >&2
    return 1
  fi
}

# Stop a node and prove that the binary it restarts on accepts its state. The first stop records
# the inventory and the identity that the final checks compare against.
prepare_switch() {
  local name="$1" bin="$2" label="$3"
  stop_node "$name"
  if [[ ! -f "$SCRIPT_DIR/output/$name.before.json" ]]; then
    # shellcheck disable=SC2046
    python3 "$INVENTORY" snapshot "$SCRIPT_DIR/output/$name.before.json" $(node_state_dirs "$name")
    record_identity "$name"
  fi
  validate_state "$name" "$bin" "$label"
}

# Stop a node and clear its state with the candidate's `node reset-data`, as an operator does when
# the candidate cannot load the state. The reset must remove the event log and leave only the
# identity in the store, and the candidate must accept what remains.
prepare_reset() {
  local name="$1"
  stop_node "$name"
  record_identity "$name"
  heading "Reset $name with the candidate binary"
  "$INTERFOLD_BIN_NEW" node reset-data --yes --name "$name" --config "$CONFIG" 2>&1 \
    | tee "$SCRIPT_DIR/output/$name.reset.txt"
  if compgen -G "$SCRIPT_DIR/.interfold/data/$name/log*" >/dev/null; then
    echo "$name: reset-data left an event log" >&2
    return 1
  fi
  validate_state "$name" "$INTERFOLD_BIN_NEW" new
  if ! grep -qF "empty store will be initialized" "$SCRIPT_DIR/output/$name.new.validate.txt"; then
    echo "$name: reset-data left protocol state in the store" >&2
    return 1
  fi
}

# Wait until a node records an E3 as complete. `reset-data` refuses to delete the key share of an
# E3 that the node has not seen complete.
wait_for_complete() {
  local name="$1" label="$2" e3_id="$3" waited=0
  until grep -qF "E3 lifecycle reached terminal stage e3_id=31337:$e3_id stage=Complete" \
    "$SCRIPT_DIR/output/$name.$label.log" 2>/dev/null; do
    if ((waited >= 120)); then
      echo "$name did not record E3 $e3_id as complete within 120 s" >&2
      return 1
    fi
    sleep 1
    waited=$((waited + 1))
  done
}

contract_address() {
  grep -A1 "$1:" "$CONFIG" | sed -n 's/.*address: *"\{0,1\}\(0x[0-9a-fA-F]*\)"\{0,1\}.*/\1/p' | head -n 1
}

registry_address() {
  contract_address ciphernode_registry
}

# The operator address and the libp2p peer ID, as the given binary reads them from the node state.
# Fails when a lookup fails or prints nothing, so an unreadable identity never compares as equal.
identity_of() {
  local bin="$1" name="$2" address peer_id
  address=$("$bin" wallet get --name "$name" --config "$CONFIG" 2>/dev/null) || return 1
  peer_id=$("$bin" net get-peer-id --name "$name" --config "$CONFIG" 2>/dev/null) || return 1
  # A log line can come before the value, so keep only the last line.
  address=${address##*$'\n'}
  peer_id=${peer_id##*$'\n'}
  if [[ -z "$address" || -z "$peer_id" ]]; then
    echo "$name: the operator address or the peer ID is empty" >&2
    return 1
  fi
  echo "$address $peer_id"
}

# Count the logs of one event on the local chain. A failed query fails, so it never reads as zero
# events.
count_logs() {
  local address="$1" signature="$2" logs
  logs=$(cast logs --from-block 0 --address "$address" "$signature" --rpc-url http://localhost:8545) ||
    return 1
  grep -c "blockNumber" <<<"$logs" || true
}

committee_node_names() {
  local e3_id="$1" addresses address
  addresses=$(cast call "$(registry_address)" "getCommitteeNodes(uint256)(address[])" "$e3_id" \
    --rpc-url http://localhost:8545 | tr -d '[] ' | tr ',' ' ')
  for address in $addresses; do
    node_name_for_address "$address"
  done
}

# Request an E3 from the minimum committee, wait for its public key in `dir`, and open its input
# window. The function sets E3_ID.
request_e3() {
  local dir="$1" request_output
  heading "Request Committee"
  set_integration_input_window
  request_output=$(pnpm committee:new \
    --network localhost \
    --input-window-start "$INPUT_WINDOW_START" \
    --input-window-end "$INPUT_WINDOW_END" \
    --e3-params "$ENCODED_PARAMS" \
    --committee-size 0)
  printf '%s\n' "$request_output"
  E3_ID=$(extract_e3_id "$request_output")
  wait_for_committee_pubkey "$E3_ID" "$dir/pubkey.bin" "${INTEGRATION_DKG_TIMEOUT:-1300}"
  advance_evm_time_past "$INPUT_WINDOW_START"
}

# Encrypt the test plaintext to the public key in `dir`, then publish an input and the ciphertext.
publish_ciphertext() {
  local e3_id="$1" dir="$2"
  heading "Mock encrypted plaintext"
  "$SCRIPT_DIR/lib/fake_encrypt.sh" --input "$dir/pubkey.bin" --output "$dir/output.bin" \
    --commitment-output "$dir/ciphertext_commitment.bin" --plaintext "$PLAINTEXT" \
    --params "$ENCODED_PARAMS"

  heading "Mock publish input e3-id"
  pnpm e3-program:publishInput --network localhost --e3-id "$e3_id" --data 0x12345678

  advance_evm_time_past "$INPUT_WINDOW_END"

  waiton "$dir/output.bin"

  heading "Publish ciphertext to EVM"
  pnpm e3:publishCiphertext \
    --e3-id "$e3_id" \
    --network localhost \
    --data-file "$dir/output.bin" \
    --ciphertext-commitment-file "$dir/ciphertext_commitment.bin" \
    --proof 0x12345678 \
    --mock-data-availability-directory "$MOCK_DATA_AVAILABILITY_DIRECTORY"
}

# Wait for the plaintext of an E3 and compare it with the test plaintext.
check_plaintext() {
  local e3_id="$1" dir="$2" actual
  wait_for_plaintext_output "$e3_id" "$dir/plaintext.txt"
  actual=$(cut -d',' -f1,2 "$dir/plaintext.txt")
  if [[ "$actual" != "$PLAINTEXT"* ]]; then
    echo "Invalid plaintext decrypted for E3 $e3_id: actual='$actual' expected='$PLAINTEXT'"
    echo "Test FAILED"
    cleanup 1
  fi
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

NOIR_DIR="$SCRIPT_DIR/.interfold/noir"
CANDIDATE_NOIR="$SCRIPT_DIR/.interfold/candidate-noir"
if [[ "$UPGRADE_SCENARIO" == "reset" ]]; then
  # The released binary's setup replaces the circuits and `bb` when it pins another circuits
  # version, as v0.17.0 does. Keep what prebuild staged for the candidate, and restore it before
  # the candidate starts. After a failed run, a rerun with --no-prebuild would keep what the
  # released binary downloaded, so the folder must match the stamp that prebuild wrote.
  PREBUILD_STAMP="$SCRIPT_DIR/.interfold/prebuild-noir.sha256"
  if ! STAGED_NOIR=$(noir_digest "$NOIR_DIR") || [[ ! -f "$PREBUILD_STAMP" ]] ||
    [[ "$STAGED_NOIR" != "$(cat "$PREBUILD_STAMP")" ]]; then
    echo "$NOIR_DIR does not hold the prebuild output. Run ./test.sh upgrade without --no-prebuild." >&2
    cleanup 1
  fi
  rm -rf "$CANDIDATE_NOIR"
  mkdir -p "$CANDIDATE_NOIR"
  cp -R "$NOIR_DIR/circuits" "$NOIR_DIR/bin" "$NOIR_DIR/version.json" "$CANDIDATE_NOIR/"
fi

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

ENCODED_PARAMS=0x$("$SCRIPT_DIR/lib/pack_e3_params.sh" \
  --moduli 0xffffee001 \
  --moduli 0xffffc4001 \
  --degree 512 \
  --plaintext-modulus 100)

FIRST_E3_ID=""
RESET_NODES=""
if [[ "$UPGRADE_SCENARIO" == "reset" ]]; then
  heading "Complete a first E3 on the released binary"
  FIRST_E3_DIR="$SCRIPT_DIR/output/first-e3"
  mkdir -p "$FIRST_E3_DIR"
  request_e3 "$FIRST_E3_DIR"
  FIRST_E3_ID="$E3_ID"
  RESET_NODES=$(committee_node_names "$FIRST_E3_ID" | tr '\n' ' ')
  if [[ "$UPGRADE_RESET" == "all" ]]; then
    RESET_NODES="$ALL_NODES"
  fi
  publish_ciphertext "$FIRST_E3_ID" "$FIRST_E3_DIR"
  check_plaintext "$FIRST_E3_ID" "$FIRST_E3_DIR"
  echo "E3 $FIRST_E3_ID is complete. Nodes to reset: [$RESET_NODES ]"
  for name in $RESET_NODES; do
    wait_for_complete "$name" old "$FIRST_E3_ID"
  done

  # Every node stops before any node starts on the candidate. The nodes share one circuits folder,
  # and each start installs the circuits that its binary pins.
  for name in $ALL_NODES; do
    if [[ " $RESET_NODES " == *" $name "* ]]; then
      prepare_reset "$name"
    else
      prepare_switch "$name" "$INTERFOLD_BIN_NEW" new
    fi
  done
  heading "Restore the candidate circuits"
  rm -rf "$NOIR_DIR/circuits" "$NOIR_DIR/bin"
  cp -R "$CANDIDATE_NOIR/circuits" "$CANDIDATE_NOIR/bin" "$NOIR_DIR/"
  cp "$CANDIDATE_NOIR/version.json" "$NOIR_DIR/version.json"
  # The candidate's setup finds its own circuits version and downloads nothing.
  "$INTERFOLD_BIN_NEW" noir setup
  for name in $ALL_NODES; do
    start_node "$INTERFOLD_BIN_NEW" "$name" new
  done
  for name in $ALL_NODES; do
    wait_for_effects "$name" new
  done
fi

request_e3 "$SCRIPT_DIR/output"

COMMITTEE=$(committee_node_names "$E3_ID" | tr '\n' ' ')
ACTIVE_AGG=$(node_name_for_address "$(wait_for_active_aggregator_address "$E3_ID")")
echo "Committee: $COMMITTEE; active aggregator: $ACTIVE_AGG"

UPGRADED=""
case "$UPGRADE_SCENARIO" in
  all|late|rollback|reset)
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
      cleanup 1
    fi
    ;;
esac

if [[ "$UPGRADE_SCENARIO" == "reset" ]]; then
  # Every node already runs the candidate. The run proves the reset path only when a reset node
  # takes part in this E3.
  reset_in_committee=0
  for name in $COMMITTEE; do
    if [[ " $RESET_NODES " == *" $name "* ]]; then
      reset_in_committee=$((reset_in_committee + 1))
    fi
  done
  if ((reset_in_committee == 0)); then
    echo "Inconclusive: committee [$COMMITTEE] has no reset node; run the scenario again" >&2
    echo "Test FAILED"
    cleanup 1
  fi
else
  echo "Scenario $UPGRADE_SCENARIO: move [$UPGRADED ] to the candidate"
  for name in $UPGRADED; do
    prepare_switch "$name" "$INTERFOLD_BIN_NEW" new
    if [[ "$UPGRADE_SCENARIO" != "late" ]]; then
      start_node "$INTERFOLD_BIN_NEW" "$name" new
    fi
  done
fi

if [[ "$UPGRADE_SCENARIO" == "rollback" ]]; then
  # Roll back only a candidate that replayed its state, joined the network, and enabled effects.
  # Let the candidates write state first, so the old binary must read state that a candidate wrote.
  for name in $UPGRADED; do
    wait_for_effects "$name" new
  done
  sleep 30
  for name in $UPGRADED; do
    if grep -E -n "Halting|panicked at|Failed to deserialize|failed to decode" \
      "$SCRIPT_DIR/output/$name.new.log"; then
      echo "$name: the candidate log shows a load or decode failure before the rollback" >&2
      cleanup 1
    fi
  done
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

publish_ciphertext "$E3_ID" "$SCRIPT_DIR/output"

if [[ "$UPGRADE_SCENARIO" == "late" ]]; then
  for name in $UPGRADED; do
    start_node "$INTERFOLD_BIN_NEW" "$name" new
  done
fi

check_plaintext "$E3_ID" "$SCRIPT_DIR/output"

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

heading "Check the chain for failures and slashing"
for e3_id in $FIRST_E3_ID $E3_ID; do
  E3_STAGE=$(cast call "$(contract_address interfold)" "getE3Stage(uint256)(uint8)" "$e3_id" \
    --rpc-url http://localhost:8545)
  if [[ "$E3_STAGE" != "5" ]]; then
    echo "E3 $e3_id is at stage $E3_STAGE, not Complete (5)" >&2
    FAILED=1
  fi
done
if ! FAILED_E3S=$(count_logs "$(contract_address interfold)" "E3Failed(uint256,uint8,uint8)") ||
  ! SLASH_PROPOSALS=$(count_logs "$(contract_address slashing_manager)" \
    "SlashProposed(uint256,uint256,address,bytes32,uint256,uint256,uint256,address,uint8)"); then
  echo "could not read the E3Failed and SlashProposed logs from the chain" >&2
  FAILED=1
elif [[ "$FAILED_E3S" != "0" || "$SLASH_PROPOSALS" != "0" ]]; then
  echo "chain shows $FAILED_E3S E3Failed and $SLASH_PROPOSALS SlashProposed events" >&2
  FAILED=1
fi

for name in $ALL_NODES; do
  stop_node "$name"
done
LAST_BIN="$INTERFOLD_BIN_NEW"
[[ "$UPGRADE_SCENARIO" == "rollback" ]] && LAST_BIN="$INTERFOLD_BIN_OLD"
for name in $UPGRADED; do
  if ! identity_after=$(identity_of "$LAST_BIN" "$name"); then
    echo "$name: could not read the operator address and peer ID after the switch" >&2
    FAILED=1
  elif [[ "$identity_after" != "$(cat "$SCRIPT_DIR/output/$name.identity.before")" ]]; then
    echo "$name: the operator address or peer ID changed across the switch" >&2
    FAILED=1
  fi
done
for name in $UPGRADED; do
  # A reset node deleted its state on purpose.
  if [[ " $RESET_NODES " == *" $name "* ]]; then
    continue
  fi
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
