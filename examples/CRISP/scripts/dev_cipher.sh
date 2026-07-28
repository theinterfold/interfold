#!/usr/bin/env bash

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/dev_config.sh"
READYFILE=$1

# nuke past installations as we are adding these nodes to the contract
rm -rf ./.interfold/data
rm -rf ./.interfold/config
rm -rf $READYFILE

PRIVATE_KEY_CN1="0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
PRIVATE_KEY_CN2="0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"
PRIVATE_KEY_CN3="0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6"
PRIVATE_KEY_CN4="0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a"
PRIVATE_KEY_CN5="0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba"

interfold wallet set --name cn1 --private-key "$PRIVATE_KEY_CN1"
interfold wallet set --name cn2 --private-key "$PRIVATE_KEY_CN2"
interfold wallet set --name cn3 --private-key "$PRIVATE_KEY_CN3"
interfold wallet set --name cn4 --private-key "$PRIVATE_KEY_CN4"
interfold wallet set --name cn5 --private-key "$PRIVATE_KEY_CN5"

load_crisp_dev_config

echo "Setting up ZK prover..."
interfold noir setup

sync_interfold_circuit_artifacts

# using & instead of -d so that wait works below
interfold nodes up -v &
SWARM_PID=$!

# `nodes up` keeps running even when every node it supervises has exited, so leaving it behind on
# an early exit would orphan it - and the next run wipes .interfold/data out from under it.
cleanup_swarm() {
  kill -TERM "$SWARM_PID" 2>/dev/null || true
}
trap cleanup_swarm EXIT

# A node counts as `Started` as soon as its process is spawned, which is earlier than the point
# where it is actually usable, so a single sample can catch a node that is about to die. Require
# the full count to hold across consecutive samples instead.
# Match the STATUS column exactly: node names come from this config, so a substring match over
# the whole line could be satisfied by a node name rather than by a real status.
EXPECTED_NODES=$(yq -r '.nodes | length' ./interfold.config.yaml)
REQUIRED_STABLE_SAMPLES=3
STABLE_SAMPLES=0
STARTED_NODES=0

for _ in $(seq 1 60); do
  STARTED_NODES=$(interfold nodes ps 2>/dev/null | awk 'NR > 1 && $2 == "Started"' | wc -l | tr -d ' ')
  if [[ "$STARTED_NODES" -eq "$EXPECTED_NODES" ]]; then
    STABLE_SAMPLES=$((STABLE_SAMPLES + 1))
  else
    STABLE_SAMPLES=0
  fi
  if [[ "$STABLE_SAMPLES" -ge "$REQUIRED_STABLE_SAMPLES" ]]; then
    break
  fi
  sleep 1
done

if [[ "$STABLE_SAMPLES" -lt "$REQUIRED_STABLE_SAMPLES" ]]; then
  echo "ERROR: only ${STARTED_NODES}/${EXPECTED_NODES} ciphernodes stayed up. Current status:" >&2
  interfold nodes ps >&2 || true
  echo "See the node output above for the cause. If it mentions a missing Cargo feature, the" >&2
  echo "installed interfold binary does not match this dev profile - re-run 'pnpm dev:setup'." >&2
  exit 1
fi

CN1=$(cat ./interfold.config.yaml | yq -r '.nodes.cn1.address')
CN2=$(cat ./interfold.config.yaml | yq -r '.nodes.cn2.address')
CN3=$(cat ./interfold.config.yaml | yq -r '.nodes.cn3.address')
CN4=$(cat ./interfold.config.yaml | yq -r '.nodes.cn4.address')
CN5=$(cat ./interfold.config.yaml | yq -r '.nodes.cn5.address')

# Add ciphernodes using variables from config.sh
pnpm ciphernode:add --ciphernode-address "$CN1" --network "localhost"
pnpm ciphernode:add --ciphernode-address "$CN2" --network "localhost"
pnpm ciphernode:add --ciphernode-address "$CN3" --network "localhost"
pnpm ciphernode:add --ciphernode-address "$CN4" --network "localhost"
pnpm ciphernode:add --ciphernode-address "$CN5" --network "localhost"

echo 1 > $READYFILE

echo "CIPHERNODES HAVE BEEN ADDED."

wait
