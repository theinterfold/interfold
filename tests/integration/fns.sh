#!/usr/bin/env bash
set -euo pipefail  # Stricter error handling

# Get the script's location
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
PLAINTEXT="4,0"

# Set by test.sh via export_integration_flags
PROOF_AGGREGATION_ENABLED="${PROOF_AGGREGATION_ENABLED:-false}"
INTEGRATION_DKG_TIMEOUT="${INTEGRATION_DKG_TIMEOUT:-1300}"
ID=$(date +%s)

if [[ "$SCRIPT_DIR" != "$(pwd)" ]]; then 
  echo "This script must be run from the test folder"
  exit 1
fi

# Environment variables
RPC_URL="ws://localhost:8545"

PRIVATE_KEY_CN1="0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
PRIVATE_KEY_CN2="0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"
PRIVATE_KEY_CN3="0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6"
PRIVATE_KEY_CN4="0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a"
PRIVATE_KEY_CN5="0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba"
CIPHERNODE_SECRET="We are the music makers and we are the dreamers of the dreams."

# These are random addresses for now
CIPHERNODE_ADDRESS_1="0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
CIPHERNODE_ADDRESS_2="0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
CIPHERNODE_ADDRESS_3="0x90F79bf6EB2c4f870365E785982E1f101E93b906"
CIPHERNODE_ADDRESS_4="0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65"
CIPHERNODE_ADDRESS_5="0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc"


if command -v interfold >/dev/null 2>&1; then
   INTERFOLD_BIN="interfold"
elif [[ -f "$ROOT_DIR/target/debug/interfold" ]]; then
   INTERFOLD_BIN="$ROOT_DIR/target/debug/interfold"
else
   cargo build --locked --bin interfold
   INTERFOLD_BIN="$ROOT_DIR/target/debug/interfold"
fi
echo "Interfold binary: $INTERFOLD_BIN"

# Function to clean up background processes
cleanup() {
    echo "Cleaning up processes..."
    jobs -p | xargs -r kill -9 2>/dev/null || true
    pkill -9 -f "target/debug/interfold" || true
    pkill -9 -f "hardhat" || true
    pkill -9 -f "anvil" || true
    exit ${1:-1}
}

heading() {
    echo ""
    echo ""
    echo "--------------------------------------------------------------"
    echo " $1     "
    echo "--------------------------------------------------------------"
    echo ""
}

strip_ansi() {
    sed 's/\x1b\[[0-9;]*m//g'
}

waiton() {
    local file_path="$1"
    local timeout="${2:-1300}"  # default ~22 minutes
    local start_time=$(date +%s)
    until [ -f "$file_path" ]; do
        if [ $(($(date +%s) - start_time)) -ge $timeout ]; then
            echo "Timeout after ${timeout}s waiting for: $file_path" >&2
            return 1
        fi
        sleep 1
    done
}

waiton-files() {
  local timeout=1300  # ~22 minutes timeout
  local start_time=$(date +%s)
  while true; do
    all_exist=true
    for file in "$@"; do
      if [ ! -f "$file" ]; then
        all_exist=false
        break
      fi
    done
    if $all_exist; then
      break
    fi
    if [ $(($(date +%s) - start_time)) -ge $timeout ]; then
      echo "Timeout waiting for files: $@" >&2
      return 1
    fi
    sleep 1
  done
}

  wait_for_committee_pubkey() {
    local e3_id="$1"
    local out_file="$2"
    local timeout="${3:-$INTEGRATION_DKG_TIMEOUT}"
    local start_time=$(date +%s)

    while true; do
      if pnpm committee:get-public-key --network localhost --e3-id "$e3_id" --out-file "$out_file" >/dev/null 2>&1; then
        return 0
      fi

      if [ $(($(date +%s) - start_time)) -ge "$timeout" ]; then
        echo "Timeout after ${timeout}s waiting for committee public key for e3=${e3_id}" >&2
        return 1
      fi

      sleep 1
    done
  }

  wait_for_plaintext_output() {
    local e3_id="$1"
    local out_file="$2"
    local timeout="${3:-1300}"
    local start_time=$(date +%s)

    while true; do
      if pnpm e3:get-plaintext --network localhost --e3-id "$e3_id" --out-file "$out_file" >/dev/null 2>&1; then
        return 0
      fi

      if [ $(($(date +%s) - start_time)) -ge "$timeout" ]; then
        echo "Timeout after ${timeout}s waiting for plaintext output for e3=${e3_id}" >&2
        return 1
      fi

      sleep 1
    done
  }

  wait_for_active_aggregator_address() {
    local e3_id="$1"
    local timeout="${2:-1300}"
    local start_time=$(date +%s)

    while true; do
      local output=""
      if output=$(pnpm committee:get-active-aggregator --network localhost --e3-id "$e3_id" 2>/dev/null); then
        echo "$output" | tail -n 1
        return 0
      fi

      if [ $(($(date +%s) - start_time)) -ge "$timeout" ]; then
        echo "Timeout after ${timeout}s waiting for active aggregator for e3=${e3_id}" >&2
        return 1
      fi

      sleep 1
    done
  }

  node_name_for_address() {
    local address="${1,,}"

    case "$address" in
      "${CIPHERNODE_ADDRESS_1,,}") echo "cn1" ;;
      "${CIPHERNODE_ADDRESS_2,,}") echo "cn2" ;;
      "${CIPHERNODE_ADDRESS_3,,}") echo "cn3" ;;
      "${CIPHERNODE_ADDRESS_4,,}") echo "cn4" ;;
      "${CIPHERNODE_ADDRESS_5,,}") echo "cn5" ;;
      *)
        echo "Unknown ciphernode address: $1" >&2
        return 1
        ;;
    esac
  }

interfold_password_set() {
  local name="$1"
  local password="$2"
  $INTERFOLD_BIN password set \
    --name $name \
    --config "$SCRIPT_DIR/interfold.config.yaml" \
    --password "$password"
}

interfold_start() {
   local name="$1"
   heading "Launch ciphernode $name"

   # convert OTEL env var to args
   local extra_args=""
   if [[ -n "${OTEL+x}" ]] && [[ -n "$OTEL" ]]; then
      extra_args="--otel=${OTEL}"
   fi

   $INTERFOLD_BIN start -v \
     --name "$name" \
     --config "$SCRIPT_DIR/interfold.config.yaml" $extra_args & 
}

interfold_nodes_up() {
   $INTERFOLD_BIN nodes up -v \
     --config "$SCRIPT_DIR/interfold.config.yaml" & 
}

interfold_nodes_down() {
  $INTERFOLD_BIN nodes down  
}

interfold_wallet_set() {
  local name="$1"
  local private_key="$2"

  $INTERFOLD_BIN wallet set \
    --name $name \
    --config "$SCRIPT_DIR/interfold.config.yaml" \
    --private-key "$private_key"
}

interfold_net_set_key() {
  local name="$1"
  local private_key="$2"

  $INTERFOLD_BIN net set-key \
    --name $name \
    --config "$SCRIPT_DIR/interfold.config.yaml" \
    --net-keypair "$private_key"
}

interfold_nodes_stop() {
  local name="$1"

  $INTERFOLD_BIN nodes stop $name -v \
    --config "$SCRIPT_DIR/interfold.config.yaml"
}

interfold_nodes_start() {
  local name="$1"

  $INTERFOLD_BIN nodes start $name -v \
    --config "$SCRIPT_DIR/interfold.config.yaml"
}

kill_proc() {
  local name=$1
  local pid=$(ps aux | grep 'interfold' | grep "\--name $name" | awk '{ print $2 }')
  echo "Killing $pid"
  kill $pid
}

kill_em_all() {
  echo "Killing interfold"
  pkill -9 -f "target/debug/interfold" || true
  pkill -9 -f "interfold start" || true
  pkill -9 -f "anvil" || true
}

launch_evm() {
  anvil --host 0.0.0.0 --chain-id 31337 --block-time 1 --mnemonic 'test test test test test test test test test test test junk' --silent &
}

ensure_process_count_equals() {
  local process_name="$1"
  local expected_count="$2"
  local actual_count=$(pgrep -f "$process_name" | wc -l)
  [ "$actual_count" -eq "$expected_count" ]
  return $?
}

gracefull_shutdown() {
  interfold_nodes_down
  echo "waiting 5 seconds for processes to shutdown"
  sleep 5
  ensure_process_count_equals "target/debug/interfold" 0 || return 1
  kill_em_all
}

daemon_query_events() {
  local name="$1"
  local output_file="${2:-$SCRIPT_DIR/output/events.txt}"

  local ctrl_port=$($INTERFOLD_BIN config get ctrl_port \
    --name $name \
    --config "$SCRIPT_DIR/interfold.config.yaml")

  local json_payload='{"command":{"EventsQuery":{"since":0,"limit":10}}}'
  curl -sf -X POST "http://127.0.0.1:${ctrl_port}" \
    -H "Content-Type: application/json" \
    -d "$json_payload" > "$output_file"

}

check_last_line() {
  local file="$1"
  local expected="$2"
  if [[ "$(tail -1 "$file")" == "$expected" ]]; then
    return 0
  else
    return 1
  fi
}

# Run this at the start of every test to ensure we start with a clean slate
kill_em_all

# Set up trap to catch errors and interrupts
trap 'cleanup $?' ERR INT TERM

$SCRIPT_DIR/lib/clean_folders.sh "$SCRIPT_DIR"
