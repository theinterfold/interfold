# Get the current block timestamp from a local EVM node
# Usage: get_evm_timestamp [rpc_url]
get_evm_timestamp() {
  local rpc_url="${1:-http://localhost:8545}" timestamp
  timestamp=$(curl -fsS -X POST "$rpc_url" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["latest",false],"id":1}' \
    | jq -er '.result.timestamp | select(type == "string" and test("^0x[0-9a-fA-F]+$"))') || return 1
  printf '%d\n' "$timestamp"
}

# Reserve time for the request, DKG, restart, and input preparation.
set_integration_input_window() {
  local timeout="${INTEGRATION_DKG_TIMEOUT:-1300}" now
  case "$timeout" in ''|*[!0-9]*|0) echo "Invalid INTEGRATION_DKG_TIMEOUT: $timeout" >&2; return 1 ;; esac
  now=$(get_evm_timestamp) || return 1
  INPUT_WINDOW_START=$((now + 60))
  INPUT_WINDOW_END=$((INPUT_WINDOW_START + 10#$timeout + 300))
}

# Mine at the requested timestamp on the local test chain. Never move time backward.
advance_evm_timestamp() {
  local target="$1" current
  current=$(get_evm_timestamp) || return 1
  if (( current < target )); then
    curl -fsS -X POST http://localhost:8545 -H "Content-Type: application/json" \
      -d "{\"jsonrpc\":\"2.0\",\"method\":\"evm_mine\",\"params\":[$target],\"id\":1}" \
      | jq -e 'has("result") and .error == null' >/dev/null
  fi
}

# Extract and validate the E3 ID printed by committee:new.
# Usage: extract_e3_id "$request_output"
extract_e3_id() {
  local request_output="$1"
  local e3_id
  e3_id=$(printf '%s\n' "$request_output" | sed -n 's/^E3_ID=//p' | tail -n 1)

  case "$e3_id" in
    ''|*[!0-9]*)
      echo "Committee request did not return a valid E3 ID" >&2
      return 1
      ;;
  esac

  printf '%s\n' "$e3_id"
}
