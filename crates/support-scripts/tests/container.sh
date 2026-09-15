#!/usr/bin/env bash

set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
START_SCRIPT="$REPOSITORY_ROOT/crates/support-scripts/ctl/start"
TEST_REVISION="abc123456"
TEST_PARENT="${TMPDIR:-/tmp}"
TEST_PARENT="${TEST_PARENT%/}"
TEST_DIRECTORIES=()

cleanup() {
  local directory
  for directory in "${TEST_DIRECTORIES[@]}"; do
    case "$directory" in
      "$TEST_PARENT"/e3-support-test.*) rm -rf -- "$directory" ;;
      *)
        echo "Refusing to remove unexpected test directory: $directory" >&2
        return 1
        ;;
    esac
  done
}
trap cleanup EXIT

interfold() {
  if [[ "${1:-}" != "rev" ]]; then
    return 1
  fi
  if [[ "$PWD" == "/" ]]; then
    printf '%s\n' "$TEST_REVISION"
  else
    printf '%s\n' "running-node-revision"
  fi
}

docker() {
  if [[ "${1:-}" == "image" && "${2:-}" == "inspect" ]]; then
    return "${LOCAL_IMAGE_STATUS:-0}"
  fi
  if [[ "${1:-}" == "pull" ]]; then
    printf 'DOCKER_PULL %s\n' "$2"
    return "${PULL_STATUS:-0}"
  fi
  if [[ "${1:-}" == "ps" ]]; then
    return 0
  fi
  if [[ "${1:-}" == "run" ]]; then
    printf 'DOCKER_RUN %s\n' "$*"
    return 0
  fi
  if [[ "${1:-}" == "exec" || "${1:-}" == "stop" ]]; then
    return 0
  fi
  echo "Unexpected docker command: $*" >&2
  return 1
}

sleep() {
  return 0
}

export TEST_REVISION
export -f interfold docker sleep

CASE_OUTPUT=""
CASE_STATUS=0

run_case() {
  local local_image_status="$1"
  local pull_status="$2"
  local image_repository="${3:-}"
  local start_args=()
  if (( $# > 3 )); then
    start_args=("${@:4}")
  fi
  local directory

  directory=$(mktemp -d "$TEST_PARENT/e3-support-test.XXXXXX")
  TEST_DIRECTORIES+=("$directory")

  set +e
  CASE_OUTPUT=$(
    cd "$directory" || exit 1
    # Keep each case independent from credentials and support settings in the parent process.
    # GitHub Actions defines PRIVATE_KEY for other jobs in this workflow.
    unset RISC0_DEV_MODE RPC_URL PRIVATE_KEY PINATA_JWT IPFS_GATEWAY_URL PROGRAM_URL
    unset BOUNDLESS_ONCHAIN BOUNDLESS_MIN_PRICE_ETH BOUNDLESS_MAX_PRICE_ETH
    unset BOUNDLESS_TIMEOUT_SECS BOUNDLESS_LOCK_TIMEOUT_SECS BOUNDLESS_RAMP_UP_SECS
    unset BOUNDLESS_LOCK_COLLATERAL_ZKC
    export LOCAL_IMAGE_STATUS="$local_image_status"
    export PULL_STATUS="$pull_status"
    if [[ -n "$image_repository" ]]; then
      export E3_SUPPORT_IMAGE_REPOSITORY="$image_repository"
    else
      unset E3_SUPPORT_IMAGE_REPOSITORY
    fi
    if (( ${#start_args[@]} > 0 )); then
      bash "$START_SCRIPT" --risc0-dev-mode false "${start_args[@]}" 2>&1
    else
      bash "$START_SCRIPT" --risc0-dev-mode false 2>&1
    fi
  )
  CASE_STATUS=$?
  set -e
}

assert_contains() {
  local expected="$1"
  if [[ "$CASE_OUTPUT" != *"$expected"* ]]; then
    echo "Expected output to contain: $expected" >&2
    echo "$CASE_OUTPUT" >&2
    exit 1
  fi
}

assert_not_contains() {
  local unexpected="$1"
  if [[ "$CASE_OUTPUT" == *"$unexpected"* ]]; then
    echo "Expected output not to contain: $unexpected" >&2
    echo "$CASE_OUTPUT" >&2
    exit 1
  fi
}

run_case 0 0
[[ "$CASE_STATUS" -eq 0 ]]
assert_not_contains "DOCKER_PULL"
assert_contains "DOCKER_RUN"
assert_contains "ghcr.io/theinterfold/e3-support:$TEST_REVISION"

run_case 1 0
[[ "$CASE_STATUS" -eq 0 ]]
assert_contains "DOCKER_PULL ghcr.io/theinterfold/e3-support:$TEST_REVISION"
assert_contains "DOCKER_RUN"

run_case 1 1
[[ "$CASE_STATUS" -ne 0 ]]
assert_contains "Support image ghcr.io/theinterfold/e3-support:$TEST_REVISION is unavailable"
assert_not_contains "DOCKER_RUN"

run_case 0 0 "registry.example/e3-support"
[[ "$CASE_STATUS" -eq 0 ]]
assert_contains "registry.example/e3-support:$TEST_REVISION"

run_case 0 0 "" \
  --ipfs-gateway-url https://dedicated.example \
  --boundless-min-price-eth 0.0001 \
  --boundless-max-price-eth 0.004 \
  --boundless-timeout-secs 2700 \
  --boundless-lock-timeout-secs 1200 \
  --boundless-ramp-up-secs 300 \
  --boundless-lock-collateral-zkc 3.5
[[ "$CASE_STATUS" -eq 0 ]]
assert_contains "--env IPFS_GATEWAY_URL"
assert_contains "--env BOUNDLESS_MIN_PRICE_ETH"
assert_contains "--env BOUNDLESS_MAX_PRICE_ETH"
assert_contains "--env BOUNDLESS_TIMEOUT_SECS"
assert_contains "--env BOUNDLESS_LOCK_TIMEOUT_SECS"
assert_contains "--env BOUNDLESS_RAMP_UP_SECS"
assert_contains "--env BOUNDLESS_LOCK_COLLATERAL_ZKC"

run_case 0 0 "" \
  --rpc-url https://rpc.example \
  --private-key credential-that-must-not-appear \
  --pinata-jwt token-that-must-not-appear
[[ "$CASE_STATUS" -eq 0 ]]
assert_contains "--env RPC_URL"
assert_contains "--env PRIVATE_KEY"
assert_contains "--env PINATA_JWT"
assert_not_contains "credential-that-must-not-appear"
assert_not_contains "token-that-must-not-appear"

UPLOAD_DIRECTORY=$(mktemp -d "$TEST_PARENT/e3-support-test.XXXXXX")
TEST_DIRECTORIES+=("$UPLOAD_DIRECTORY")
PROGRAM_DIRECTORY="$UPLOAD_DIRECTORY/target/riscv-guest/methods/guests/riscv32im-risc0-zkvm-elf/release"
mkdir -p "$PROGRAM_DIRECTORY"
printf 'cached-program' > "$PROGRAM_DIRECTORY/program.bin"
sha256sum "$PROGRAM_DIRECTORY/program.bin" | awk '{print $1}' > "$UPLOAD_DIRECTORY/target/.program_hash"
printf 'https://gateway.pinata.cloud/ipfs/bafytestcid\n' > "$UPLOAD_DIRECTORY/target/.program_url"
(
  cd "$UPLOAD_DIRECTORY"
  bash "$REPOSITORY_ROOT/crates/support/scripts/container/upload.sh" \
    --pinata-jwt test-jwt \
    --ipfs-gateway-url https://dedicated.example/
)
[[ "$(cat "$UPLOAD_DIRECTORY/target/.program_url")" == "https://dedicated.example/ipfs/bafytestcid" ]]

echo "Support image container tests passed."
