// SPDX-License-Identifier: LGPL-3.0-only
import { actionDeploy, actionProposeSafe } from "./actions";
import { arg } from "./cli";
import { actionValidate } from "./validate";

function printHelp(): void {
  console.log(`
Interfold protocol deployment

Actions:
  --action deploy       Deploy protocol contracts and write one Safe wiring batch
  --action propose-safe Propose the written Safe batch through the Safe SDK
  --action validate     Validate after the Safe batch executes

Examples:
  pnpm protocol --network sepolia --action deploy --config packages/interfold-contracts/deploy/protocol/sepolia-protocol.config.json --propose-safe
  pnpm protocol --network sepolia --action propose-safe --config packages/interfold-contracts/deploy/protocol/sepolia-protocol.config.json
  pnpm protocol --network sepolia --action validate --config packages/interfold-contracts/deploy/protocol/sepolia-protocol.config.json

Flags:
  --sync-integration-config  Also update tests/integration/interfold.config.yaml
  --safe 0x...               Fill a zero safe placeholder
  --fold 0x...               Fill a zero FOLD placeholder
  --bonding-registry 0x...   Fill a zero BondingRegistry proxy placeholder
  --bonding-registry-proxy-admin 0x...
  --fee-token 0x...
  --protocol-treasury 0x...
  --slashed-funds-treasury 0x...
  --slasher 0x...
`);
}

export async function main(): Promise<void> {
  const action = (arg("action") ?? "help").toLowerCase();
  if (action === "help") return printHelp();
  if (action === "deploy") return actionDeploy();
  if (action === "propose-safe") return actionProposeSafe();
  if (action === "validate") return actionValidate();
  throw new Error(`Unknown --action: ${action}`);
}
