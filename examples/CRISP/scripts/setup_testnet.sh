#!/usr/bin/env bash

set -euo pipefail

export CARGO_INCREMENTAL=1

# nuke past installations as we are adding these nodes to the contract
rm -rf ./.interfold/data
rm -rf ./.interfold/config

cleanup() {
  echo "Cleaning up processes..."
  pkill -9 -f "interfold start"
  sleep 1
  
  # Kill any remaining background jobs from this script
  jobs -p | xargs kill -9 2>/dev/null || true
  
  # Give processes a moment to terminate
  sleep 1

  
  echo "Cleanup complete"
  exit 0
}

trap cleanup INT TERM

echo "TESTNET SCRIPT STARTING..."

# Read .env
if [ ! -f .env ]; then
  echo "Error: .env file not found. Please copy .env.example to .env and configure it."
  exit 1
fi
source .env 

PRIVATE_KEY_ADMIN="${PRIVATE_KEY_ADMIN:-${PRIVATE_KEY_AG:-}}"

if [ -z "$PRIVATE_KEY_ADMIN" ]; then
  echo "Error: PRIVATE_KEY_ADMIN (or legacy PRIVATE_KEY_AG) must be set in .env"
  exit 1
fi

interfold wallet set --name cn1 --private-key "$PRIVATE_KEY_CN1"
interfold wallet set --name cn2 --private-key "$PRIVATE_KEY_CN2"
interfold wallet set --name cn3 --private-key "$PRIVATE_KEY_CN3"
interfold wallet set --name cn4 --private-key "$PRIVATE_KEY_CN4"
interfold wallet set --name cn5 --private-key "$PRIVATE_KEY_CN5"

# using & instead of -d so that wait works below
interfold nodes up -v &

sleep 2

CN1=$(yq -r '.nodes.cn1.address' ./interfold.config.yaml)
CN2=$(yq -r '.nodes.cn2.address' ./interfold.config.yaml)
CN3=$(yq -r '.nodes.cn3.address' ./interfold.config.yaml)
CN4=$(yq -r '.nodes.cn4.address' ./interfold.config.yaml)
CN5=$(yq -r '.nodes.cn5.address' ./interfold.config.yaml)

echo "Minting tokens" 

# The admin/deployer account performs owner-only setup tasks during testnet bootstrap
export PRIVATE_KEY="$PRIVATE_KEY_ADMIN"

pnpm ciphernode:mint:tokens --ciphernode-address "$CN1" --network "sepolia"
pnpm ciphernode:mint:tokens --ciphernode-address "$CN2" --network "sepolia"
pnpm ciphernode:mint:tokens --ciphernode-address "$CN3" --network "sepolia"
pnpm ciphernode:mint:tokens --ciphernode-address "$CN4" --network "sepolia"
pnpm ciphernode:mint:tokens --ciphernode-address "$CN5" --network "sepolia"

echo "Adding ciphernodes to the contract"

export PRIVATE_KEY="$PRIVATE_KEY_CN1"
pnpm ciphernode:add:self --network "sepolia"
export PRIVATE_KEY="$PRIVATE_KEY_CN2"
pnpm ciphernode:add:self --network "sepolia"
export PRIVATE_KEY="$PRIVATE_KEY_CN3"
pnpm ciphernode:add:self --network "sepolia"
export PRIVATE_KEY="$PRIVATE_KEY_CN4"
pnpm ciphernode:add:self --network "sepolia"
export PRIVATE_KEY="$PRIVATE_KEY_CN5"
pnpm ciphernode:add:self --network "sepolia"

echo "CIPHERNODES HAVE BEEN ADDED."

# Reset the private key to the admin account for any subsequent contract operations
export PRIVATE_KEY="$PRIVATE_KEY_ADMIN"

# wait

concurrently -kr \
  --names "PROGRAM SERVER,CRISP SERVER" \
  --prefix-colors "blue,green" \
  "./scripts/dev_program.sh" \
  "./scripts/dev_server.sh" 