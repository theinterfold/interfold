// SPDX-License-Identifier: LGPL-3.0-only
import { actionPlan } from "./actions";
import { actionBidClaim } from "./bidClaim";
import { arg } from "./cli";
import {
  actionAcceptOwnership,
  actionDeploy,
  actionProposeSafe,
} from "./deploy";
import { actionFullTest } from "./fullTest";
import { actionPrepare } from "./prepare";
import { actionValidate } from "./validate";

function printHelp(): void {
  console.log(`
Interfold FOLD sale pipeline

One script, selected by --action:
  --action prepare      Deploy Safe-owned MockBondingRegistry proxy + sale deployer
  --action plan         Predict FOLD/CCA and write the plan
  --action deploy       Operator submits deploySale
  --action propose-safe Propose FOLD.acceptOwnership() through the Safe SDK
  --action validate     Check FOLD/CCA/Safe invariants
  --action bid-claim    Submit a CCA bid, exit, and claim FOLD
  --action full-test    Self-contained Sepolia/local rehearsal

Common flags:
  --safe 0x...              Required for --action prepare unless SAFE_ADDRESS is set
  --config <file>           Defaults to packages/interfold-contracts/deploy/sale/<network>-sale.config.json
                           prepare auto-forks to <name>-2.config.json if this already exists
  --plan <file>             Optional plan path override
  --deployment <file>       Optional deployment path override
  --safe-transactions <file> Optional manual Safe fallback batch path
  --mock-cca                Local fallback only; Sepolia/mainnet use real CCA factories by default
  --predicate-registry 0x... Deploy a Safe-owned Predicate validation hook
  --predicate-policy-id x... Predicate policy/verification hash for that hook
  --predicate-hook 0x...     Use an already deployed validation hook
  --hook-data 0x...          Encoded Predicate attestation for --action bid-claim
  --auction-duration-blocks N  CCA length in blocks (default 40)
  --cca-offset-seconds N    Seconds until FOLD CCA_START from now (default 86400 = 1 day)
  --cca-duration-seconds N  Seconds FOLD CCA lasts (default 604800 = 7 days)

Examples:
  pnpm sale --network sepolia --action full-test
  pnpm sale --network mainnet --action prepare --safe 0xSafe --config packages/interfold-contracts/deploy/sale/mainnet-sale.config.json
  pnpm sale --network mainnet --action plan --config packages/interfold-contracts/deploy/sale/mainnet-sale.config.json
  pnpm sale --network mainnet --action deploy --config packages/interfold-contracts/deploy/sale/mainnet-sale.config.json --propose-safe
  pnpm sale --network mainnet --action propose-safe --config packages/interfold-contracts/deploy/sale/mainnet-sale.config.json
`);
}

export async function main(): Promise<void> {
  const action = (arg("action") ?? "help").toLowerCase();
  if (action === "help") return printHelp();
  if (action === "prepare") return actionPrepare();
  if (action === "plan") return void (await actionPlan());
  if (action === "deploy") return actionDeploy();
  if (action === "propose-safe") return actionProposeSafe();
  if (action === "accept-ownership") return actionAcceptOwnership();
  if (action === "validate") return actionValidate();
  if (action === "bid-claim") return actionBidClaim();
  if (action === "full-test") return actionFullTest();
  throw new Error(`Unknown --action: ${action}`);
}
