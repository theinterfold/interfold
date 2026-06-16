// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import hre from "hardhat";

import { deployAndSaveAllVerifiers } from "./deployAndSave/verifiers";

/**
 * Standalone script to deploy only the circuit verifier contracts.
 * Usage: hardhat run scripts/deployVerifiers.ts --network <network>
 */
const main = async () => {
  console.log("Deploying circuit verifier contracts...\n");

  const verifierDeployments = await deployAndSaveAllVerifiers(hre);
  const entries = Object.entries(verifierDeployments);

  if (entries.length === 0) {
    console.log(
      "No verifier contracts found in contracts/verifiers/bfv/honk/.",
    );
    return;
  }

  console.log(`
    ============================================
    Verifier Deployment Complete!
    ============================================`);
  for (const [name, address] of entries) {
    console.log(`    ${name}: ${address}`);
  }
  console.log(`    ============================================
  `);
};

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
