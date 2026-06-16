// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import hre from "hardhat";

import { upgradeAndSaveInterfold } from "../deployAndSave/interfold";
import { getDeploymentChain, readDeploymentArgs } from "../utils";

/**
 * Upgrades the Interfold contract implementation and saves the deployment arguments
 * This keeps the same proxy address, only updates the implementation
 */
export const upgradeInterfold = async () => {
  const { ethers } = await hre.network.connect();
  const [signer] = await ethers.getSigners();
  const signerAddress = await signer.getAddress();
  const chain = getDeploymentChain(hre);
  console.log("Signer:", signerAddress);

  const preDeployedArgs = readDeploymentArgs("Interfold", chain);
  if (!preDeployedArgs?.address) {
    throw new Error(
      "Interfold proxy not found. Deploy first before upgrading.",
    );
  }

  if (!preDeployedArgs?.proxyRecords?.implementationAddress) {
    throw new Error(
      "Existing deployment is not proxy-based. Cannot upgrade non-proxy deployments.",
    );
  }

  console.log(
    "Interfold Proxy Address (from deployments):",
    preDeployedArgs.address,
  );

  const code = await ethers.provider.getCode(preDeployedArgs.address);
  if (code === "0x") {
    throw new Error(
      `No contract found at proxy address ${preDeployedArgs.address}`,
    );
  }
  console.log("Proxy contract exists on-chain");

  const { interfold, implementationAddress } = await upgradeAndSaveInterfold({
    ownerAddress: signerAddress,
    hre,
  });

  const interfoldAddress = await interfold.getAddress();

  console.log(`
    ============================================
    Upgrade Complete!
    ============================================
    Proxy Address: ${interfoldAddress}
    New Implementation: ${implementationAddress}
    ============================================
  `);
};

upgradeInterfold().catch((error) => {
  console.error(error);
  process.exit(1);
});
