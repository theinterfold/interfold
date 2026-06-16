// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import hre from "hardhat";

import { getDeploymentChain } from "./utils";
import { verifyContracts } from "./verify";

async function main() {
  const chain = getDeploymentChain(hre);

  verifyContracts(chain);
}

main().catch((error) => {
  console.error(error);
});
