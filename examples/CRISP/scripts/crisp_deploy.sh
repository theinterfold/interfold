#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/dev_config.sh"

load_crisp_dev_config
print_crisp_dev_config_summary

echo "Deploying CRISP contracts..."

export PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
export USE_MOCKS=true
export DEPLOY_INTERFOLD=true

cd "${CRISP_ROOT}/packages/crisp-contracts"

pnpm clean:deployments --network localhost

if [[ "$CRISP_PROOF_AGGREGATION_ENABLED" == "true" ]]; then
  export ENABLE_ZK_VERIFICATION=true
  echo "Deploy: ENABLE_ZK_VERIFICATION=true (BfvPkVerifier + fold attestation)"
else
  unset ENABLE_ZK_VERIFICATION
  echo "Deploy: mock BFV verifiers (ENABLE_ZK_VERIFICATION unset)"
fi

pnpm deploy:contracts --network localhost

apply_crisp_dev_config_to_server_env
