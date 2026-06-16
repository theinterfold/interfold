#!/usr/bin/env bash

set -e

# Check if pnpm is available
if ! command -v pnpm &> /dev/null; then
    echo "ERROR: pnpm is not installed or not in PATH"
    echo "Please install pnpm or tmux to run this script"
    exit 1
fi

# Run all processes concurrently using pnpm
pnpm concurrently \
    --names "FRONTEND,EVM,CIPHER,SERVER,PROGRAM" \
    --prefix-colors "blue,cyan,magenta,yellow,green" \
    --kill-others-on-fail \
    "pnpm dev:frontend" \
    "anvil --host 0.0.0.0 --chain-id 31337 --block-time 1 --mnemonic 'test test test test test test test test test test test junk' --silent" \
    "pnpm dev:ciphernodes" \
    "TEST_MODE=1 pnpm dev:server" \
    "interfold program start"

