# Get the current block timestamp from a local EVM node
# Usage: get_evm_timestamp [rpc_url]
get_evm_timestamp() {
  local rpc_url="${1:-http://localhost:8545}"
  curl -s -X POST "$rpc_url" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["latest",false],"id":1}' \
    | jq -r '.result.timestamp' | xargs printf "%d\n"
}

# Move the dev chain's clock just past an absolute deadline.
#
# The input window has to outlast a real DKG, because a committee published after
# `inputWindowEnd` is refused by `validateCommitteePublication`. That makes the window
# minutes wide, so waiting for it in wall-clock time would add those minutes to every
# run. `evm_increaseTime` jumps the chain instead and keeps the suite at DKG speed.
# A no-op when the deadline has already passed.
#
# Usage: advance_evm_time_past <unix_timestamp> [rpc_url]
advance_evm_time_past() {
  local target="$1"
  local rpc_url="${2:-http://localhost:8545}"
  local now
  now=$(get_evm_timestamp "$rpc_url")
  if ((now > target)); then
    return 0
  fi
  local delta=$((target - now + 1))
  curl -s -X POST "$rpc_url" \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"evm_increaseTime\",\"params\":[$delta],\"id\":1}" \
    >/dev/null
  curl -s -X POST "$rpc_url" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"evm_mine","params":[],"id":1}' \
    >/dev/null
  local reached
  reached=$(get_evm_timestamp "$rpc_url")
  if ((reached <= target)); then
    echo "Failed to advance chain time past $target (still at $reached)" >&2
    return 1
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
