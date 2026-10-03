# Get the current block timestamp from a local EVM node
# Usage: get_evm_timestamp [rpc_url]
get_evm_timestamp() {
  local rpc_url="${1:-http://localhost:8545}"
  curl -s -X POST "$rpc_url" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["latest",false],"id":1}' \
    | jq -r '.result.timestamp' | xargs printf "%d\n"
}

# Check which committee sizes the local deployment configured. With mock verifiers it configures
# every size (0, 1 and 2). The ZK verifiers check one committee's H and T, so with them it
# configures one size. Interfold itself rejects an [H, N] pair that does not match the size.
# Usage: check_committee_sizes <deployed_contracts.json> <zk verification true|false> [rpc_url]
check_committee_sizes() {
  local deployments="$1" zk="$2" rpc_url="${3:-http://localhost:8545}"
  local interfold size total configured=0 expected=3
  interfold=$(jq -r '.localhost.Interfold.address' "$deployments")
  for size in 0 1 2; do
    total=$(cast call "$interfold" "committeeThresholds(uint8,uint256)(uint32)" "$size" 1 \
      --rpc-url "$rpc_url") || return 1
    if [[ "$total" != "0" ]]; then
      configured=$((configured + 1))
    fi
  done
  if [[ "$zk" == "true" ]]; then
    expected=1
  fi
  if ((configured != expected)); then
    echo "The deployment configured $configured committee sizes; expected $expected" >&2
    return 1
  fi
  echo "The deployment configured $configured committee sizes"
}

# Set INPUT_WINDOW_START/END. The committee cannot publish its key after the input window
# closes (`validateCommitteePublication`), so the window must outlast the DKG timeout plus
# restart and input preparation. The start leaves 60 seconds for the committee request.
set_integration_input_window() {
  local now
  now=$(get_evm_timestamp)
  INPUT_WINDOW_START=$((now + 60))
  INPUT_WINDOW_END=$((INPUT_WINDOW_START + ${INTEGRATION_INPUT_WINDOW_SECONDS:-$((INTEGRATION_DKG_TIMEOUT + 300))}))
}

# Move the dev chain's clock just past an absolute deadline.
#
# The input window is minutes wide, so waiting for it in wall-clock time would add those
# minutes to every run. `evm_increaseTime` jumps the chain instead and keeps the suite at
# DKG speed. A no-op when the deadline has already passed.
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

# Print the SHA-256 of stdin. Linux has sha256sum; macOS has shasum.
sha256_of_stdin() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | cut -d' ' -f1
  else
    shasum -a 256 | cut -d' ' -f1
  fi
}

# Print one digest of the circuits, the pinned versions, and `bb` in a noir folder.
# Usage: noir_digest <noir dir>
noir_digest() {
  local noir_dir="$1"
  (
    cd "$noir_dir" || exit 1
    find circuits bin version.json -type f | LC_ALL=C sort | while IFS= read -r file; do
      printf '%s %s\n' "$(sha256_of_stdin <"$file")" "$file"
    done
  ) | sha256_of_stdin
}
