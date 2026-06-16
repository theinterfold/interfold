#!/usr/bin/env bash

set -eu  # Exit immediately if a command exits with a non-zero status

# Get the directory of the currently executing script
THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Source the file from the same directory
source "$THIS_DIR/fns.sh"
source "$THIS_DIR/lib/utils.sh"

heading "Start the EVM node"

launch_evm

until curl -sf -X POST http://localhost:8545 -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' > /dev/null; do
  sleep 1
done

pnpm evm:clean

if [[ "${PROOF_AGGREGATION_ENABLED:-false}" == "true" ]]; then
  ENABLE_ZK_VERIFICATION=true pnpm evm:deploy
else
  pnpm evm:deploy
fi

(cd "$ROOT_DIR/packages/interfold-contracts" && pnpm utils:sync-integration-config)

interfold_wallet_set cn1 "$PRIVATE_KEY_CN1"
interfold_wallet_set cn2 "$PRIVATE_KEY_CN2"
interfold_wallet_set cn3 "$PRIVATE_KEY_CN3"
interfold_wallet_set cn4 "$PRIVATE_KEY_CN4"
interfold_wallet_set cn5 "$PRIVATE_KEY_CN5"

heading "Setup ZK prover"
$INTERFOLD_BIN noir setup

# start swarm
interfold_nodes_up

waiton-files "$ROOT_DIR/target/debug/fake_encrypt"

heading "Add ciphernode $CIPHERNODE_ADDRESS_1"
pnpm ciphernode:add --ciphernode-address $CIPHERNODE_ADDRESS_1 --network localhost

heading "Add ciphernode $CIPHERNODE_ADDRESS_2"
pnpm ciphernode:add --ciphernode-address $CIPHERNODE_ADDRESS_2 --network localhost

heading "Add ciphernode $CIPHERNODE_ADDRESS_3"
pnpm ciphernode:add --ciphernode-address $CIPHERNODE_ADDRESS_3 --network localhost

heading "Add ciphernode $CIPHERNODE_ADDRESS_4"
pnpm ciphernode:add --ciphernode-address $CIPHERNODE_ADDRESS_4 --network localhost

heading "Add ciphernode $CIPHERNODE_ADDRESS_5"
pnpm ciphernode:add --ciphernode-address $CIPHERNODE_ADDRESS_5 --network localhost

heading "Request Committee"

ENCODED_PARAMS=0x$($SCRIPT_DIR/lib/pack_e3_params.sh \
  --moduli 0xffffee001 \
  --moduli 0xffffc4001 \
  --degree 512 \
  --plaintext-modulus 100)

CURRENT_TIMESTAMP=$(get_evm_timestamp)
INPUT_WINDOW_START=$((CURRENT_TIMESTAMP + 20))
INPUT_WINDOW_END=$((CURRENT_TIMESTAMP + 30))

pnpm committee:new \
  --network localhost \
  --input-window-start "$INPUT_WINDOW_START" \
  --input-window-end "$INPUT_WINDOW_END" \
  --e3-params "$ENCODED_PARAMS" \
  --committee-size 0 \
  --proof-aggregation-enabled "${PROOF_AGGREGATION_ENABLED:-false}"

wait_for_committee_pubkey 0 "$SCRIPT_DIR/output/pubkey.bin" "${INTEGRATION_DKG_TIMEOUT:-1300}"

ACTIVE_AGG_ADDRESS=$(wait_for_active_aggregator_address 0)
if ! ACTIVE_AGG=$(node_name_for_address "$ACTIVE_AGG_ADDRESS"); then
  echo "Failed to resolve active aggregator node name for address: $ACTIVE_AGG_ADDRESS" >&2
  exit 1
fi

if [[ -z "$ACTIVE_AGG" ]]; then
  echo "Resolved empty active aggregator node name for address: $ACTIVE_AGG_ADDRESS" >&2
  exit 1
fi

# kill active aggregator
interfold_nodes_stop "$ACTIVE_AGG"

sleep 15

# relaunch the active aggregator
interfold_nodes_start "$ACTIVE_AGG"

sleep 5

heading "Mock encrypted plaintext"
$SCRIPT_DIR/lib/fake_encrypt.sh --input "$SCRIPT_DIR/output/pubkey.bin" --output "$SCRIPT_DIR/output/output.bin" --plaintext "$PLAINTEXT" --params "$ENCODED_PARAMS"

heading "Mock publish input e3-id"
pnpm e3-program:publishInput --network localhost  --e3-id 0 --data 0x12345678

sleep 6 # wait for input deadline to pass

waiton "$SCRIPT_DIR/output/output.bin"

heading "Publish ciphertext to EVM"
pnpm e3:publishCiphertext --e3-id 0 --network localhost --data-file "$SCRIPT_DIR/output/output.bin" --proof 0x12345678

wait_for_plaintext_output 0 "$SCRIPT_DIR/output/plaintext.txt"

ACTUAL=$(cut -d',' -f1,2 $SCRIPT_DIR/output/plaintext.txt)

# Assume plaintext is shorter

if [[ "$ACTUAL" != "$PLAINTEXT"* ]]; then
  echo "Invalid plaintext decrypted: actual='$ACTUAL' expected='$PLAINTEXT'"
  echo "Test FAILED"
  exit 1
fi

heading "Test PASSED !"
echo -e "\033[32m                                                              
                                               ██████         
                                             ██████           
                                           ██████             
                                         ██████               
                                       ██████                 
                                     ██████                   
                       ██          ██████                     
                       ████      ██████                       
                       ██████  ██████                         
                        ██████████                            
                         ████████                             
                          ██████                              
                           ████                               
                            ██                                
                                                              \033[0m"


gracefull_shutdown
