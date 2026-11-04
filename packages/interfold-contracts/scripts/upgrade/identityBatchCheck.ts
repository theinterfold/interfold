// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
//
// Checks a written identity batch before the Safe signs it. On a fresh Anvil fork of the network,
// it sends the batch exactly as governance will (with Aragon, the proposer Safe calls the Admin
// plugin), then checks that counted owner capacity covers the largest committee one second before
// the next block, and that the transaction fits the block gas limit. It refuses a batch past the
// deadline that `enforce` or `revoke` wrote into the plan.
//
// Usage (from packages/interfold-contracts):
//   FORK_URL=<RPC of the network> tsx scripts/upgrade/identityBatchCheck.ts \
//     --network mainnet --stage <prepare|enforce|relax|revoke|rotate-verifier>
//
// ANVIL_PORT sets the fork's port (default 18546).
import path from "node:path";
import { pathToFileURL } from "node:url";

import { arg } from "../protocol/cli";
import { readJson } from "../protocol/files";
import { loadConfig } from "../protocol/values";
import { executeIdentityBatch, ownerCapacity, startFork } from "./identityFork";
import { type IdentityGatePlan, planPath } from "./identityGate";
import { requiredActiveOperators } from "./v19Cutover";

/** The gas cap of one transaction (EIP-7825). */
const TRANSACTION_GAS_CAP = 16_777_216n;

export async function checkIdentityBatch(): Promise<void> {
  const forkUrl = process.env.FORK_URL;
  if (!forkUrl) throw new Error("Set FORK_URL to an RPC of the network");
  const stage = arg("stage");
  if (!stage) {
    throw new Error(
      "Pass --stage prepare|enforce|relax|revoke|rotate-verifier",
    );
  }
  const config = loadConfig();
  const plan = readJson<IdentityGatePlan>(planPath(config));
  const deadline = plan.deadlines?.[stage];
  if (deadline !== undefined && Date.now() / 1000 > Number(deadline)) {
    throw new Error(
      `The ${stage} batch had to execute by ${new Date(Number(deadline) * 1000).toISOString()}; write it again`,
    );
  }

  const fork = await startFork({
    forkUrl,
    port: Number(process.env.ANVIL_PORT ?? 18546),
  });
  try {
    const gas = await executeIdentityBatch(fork.provider, config, stage);
    const block = await fork.provider.getBlock("latest");
    const capacity = await ownerCapacity(fork.provider, plan.bondingRegistry);
    const needed = requiredActiveOperators(
      config.interfold.committeeThresholds,
      config.chainId,
      arg("sepolia-committee-size"),
    );
    const largest = gas.reduce((a, b) => (a > b ? a : b), 0n);
    console.log(`
Identity ${stage} batch replayed
  transactions:    ${gas.length} (gas ${gas.join(", ")})
  block gas limit: ${block!.gasLimit}
  owner capacity:  ${capacity} (needed ${needed})
`);
    const failures: string[] = [];
    if (capacity < needed) {
      failures.push(
        `counted owner capacity is ${capacity}; the largest committee needs ${needed}, so requests would fail`,
      );
    }
    if (largest * 2n > block!.gasLimit) {
      failures.push(
        `a transaction used ${largest} gas, more than half the block gas limit ${block!.gasLimit}; split the batch`,
      );
    }
    // Governance sends the batch with a gas limit about 1.5 times the estimate, and one
    // transaction may use at most 16,777,216 gas (EIP-7825).
    if (largest * 3n > TRANSACTION_GAS_CAP * 2n) {
      failures.push(
        `a transaction used ${largest} gas; with a 1.5x gas limit it passes the ${TRANSACTION_GAS_CAP} gas cap of one transaction (EIP-7825), so split the batch`,
      );
    }
    if (failures.length > 0) {
      throw new Error(
        `Identity ${stage} batch check failed:\n  ${failures.join("\n  ")}`,
      );
    }
    console.log(`Identity ${stage} batch check passed`);
  } finally {
    fork.stop();
  }
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
  checkIdentityBatch().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}
