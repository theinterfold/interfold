#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
#
# CKKS salary-survey DEMO ENVIRONMENT: boots the full stack (anvil +
# contracts with the CKKS E3 program + 5 real ciphernodes) and then
# WAITS, so the webapp in demo/ckks-salary-survey can drive the private
# statistics survey interactively.
#
#   Terminal 1:  cd tests/integration && ./ckks-salary-env.sh
#   Terminal 2:  node demo/ckks-salary-survey/server.mjs   (then open the URL)
#
# Ctrl-C tears everything down.

set -eu

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

source "$THIS_DIR/fns.sh"
source "$THIS_DIR/lib/utils.sh"

trap 'cleanup 0' INT TERM

heading "Start the EVM node"
launch_evm

until curl -sf -X POST http://localhost:8545 -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' > /dev/null; do
  sleep 1
done

pnpm evm:clean

heading "Deploy contracts (mock verifiers; registers CKKS E3 program)"
pnpm evm:deploy

heading "Sync integration config"
(cd "$ROOT_DIR/packages/interfold-contracts" && pnpm utils:sync-integration-config)

# Fresh node state BEFORE wallet setup (wallets are stored under
# .interfold/data — wiping after interfold_wallet_set leaves nodes with
# 'No private key found in repository' and DKG never starts). Stale event
# logs from a previous chain break recovery, and ceremony runs grow the
# data dir multi-GB.
rm -rf "$THIS_DIR/.interfold/data"

interfold_wallet_set cn1 "$PRIVATE_KEY_CN1"
interfold_wallet_set cn2 "$PRIVATE_KEY_CN2"
interfold_wallet_set cn3 "$PRIVATE_KEY_CN3"
interfold_wallet_set cn4 "$PRIVATE_KEY_CN4"
interfold_wallet_set cn5 "$PRIVATE_KEY_CN5"

heading "Setup ZK prover"
$INTERFOLD_BIN noir setup

# Relin ceremony for the statistics mode (ParamSet 3): the nodes derive
# the single ceremony level (0) from the E3's ParamSet — no configuration.
# The joint key normally lands under each node's data dir
# (<data_dir>/<node>/ckks/relin-keys/<chain:e3_id>/rlk_level_0.bin); the
# demo server reads keys from CKKS_RELIN_KEY_DIR, so we set that OVERRIDE
# here for the nodes and the server alike.
export CKKS_RELIN_KEY_DIR="${CKKS_RELIN_KEY_DIR:-/tmp/ckks-relin-keys}"
mkdir -p "$CKKS_RELIN_KEY_DIR"

interfold_nodes_up

echo "waiting on binaries and utilities..."
# CKKS_TOOLS_PROFILE=release selects the release tools (the node binary is
# chosen via INTERFOLD_BIN; release strongly recommended — debug-build
# ceremony generation blocks the node event loop).
TOOLS_DIR="$ROOT_DIR/target/${CKKS_TOOLS_PROFILE:-debug}"
waiton-files "$TOOLS_DIR/ckks_encrypt" "$TOOLS_DIR/ckks_stats_eval" "$TOOLS_DIR/pack_ckks_params" "$TOOLS_DIR/ckks_participant"

sleep 4

for addr in "$CIPHERNODE_ADDRESS_1" "$CIPHERNODE_ADDRESS_2" "$CIPHERNODE_ADDRESS_3" "$CIPHERNODE_ADDRESS_4" "$CIPHERNODE_ADDRESS_5"; do
  heading "Add ciphernode $addr"
  pnpm ciphernode:add --ciphernode-address "$addr" --network localhost
done

heading "DEMO ENVIRONMENT READY"
echo ""
echo "  Chain:        http://localhost:8545 (anvil)"
echo "  Ciphernodes:  5 processes up, registered"
echo "  CKKS program: registered (program address => protocol)"
echo ""
echo "  Now run:      node demo/ckks-salary-survey/server.mjs"
echo ""
echo "  Ctrl-C here tears the whole environment down."
echo ""

# Keep the environment alive until interrupted.
while true; do sleep 3600; done
