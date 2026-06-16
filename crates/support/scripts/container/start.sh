#!/usr/bin/env bash

# Clear any existing environment variables
unset RISC0_DEV_MODE RPC_URL PRIVATE_KEY PINATA_JWT PROGRAM_URL BOUNDLESS_ONCHAIN
unset BOUNDLESS_MIN_PRICE_ETH BOUNDLESS_MAX_PRICE_ETH
unset BOUNDLESS_TIMEOUT_SECS BOUNDLESS_LOCK_TIMEOUT_SECS BOUNDLESS_RAMP_UP_SECS BOUNDLESS_LOCK_COLLATERAL_ZKC

# Parse command line arguments
POSITIONAL=()
while [[ $# -gt 0 ]]; do
  case $1 in
    --risc0-dev-mode)
      export RISC0_DEV_MODE="$2"
      shift 2
      ;;
    --rpc-url)
      export RPC_URL="$2"
      shift 2
      ;;
    --private-key)
      export PRIVATE_KEY="$2"
      shift 2
      ;;
    --pinata-jwt)
      export PINATA_JWT="$2"
      shift 2
      ;;
    --program-url)
      export PROGRAM_URL="$2"
      shift 2
      ;;
    --boundless-onchain)
      export BOUNDLESS_ONCHAIN="$2"
      shift 2
      ;;
    --boundless-min-price-eth)
      export BOUNDLESS_MIN_PRICE_ETH="$2"
      shift 2
      ;;
    --boundless-max-price-eth)
      export BOUNDLESS_MAX_PRICE_ETH="$2"
      shift 2
      ;;
    --boundless-timeout-secs)
      export BOUNDLESS_TIMEOUT_SECS="$2"
      shift 2
      ;;
    --boundless-lock-timeout-secs)
      export BOUNDLESS_LOCK_TIMEOUT_SECS="$2"
      shift 2
      ;;
    --boundless-ramp-up-secs)
      export BOUNDLESS_RAMP_UP_SECS="$2"
      shift 2
      ;;
    --boundless-lock-collateral-zkc)
      export BOUNDLESS_LOCK_COLLATERAL_ZKC="$2"
      shift 2
      ;;
    *)
      POSITIONAL+=("$1")
      shift
      ;;
  esac
done

set -- "${POSITIONAL[@]}" 

CARGO_INCREMENTAL=1

# Default to dev mode if no Boundless configuration provided
if [ -z "$RISC0_DEV_MODE" ]; then
  if [ -z "$RPC_URL" ]; then
    export RISC0_DEV_MODE=1
    echo "No Boundless config found, defaulting to dev mode"
  fi
fi

echo "RISC0_DEV_MODE=$RISC0_DEV_MODE"
[ -n "$RPC_URL" ] && echo "Using Boundless (RPC: $RPC_URL)"

exec cargo run --bin e3-support-app "$@"
