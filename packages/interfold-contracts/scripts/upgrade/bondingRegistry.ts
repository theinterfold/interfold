// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import hre from "hardhat";

import { upgradeAndSaveBondingRegistry } from "../deployAndSave/bondingRegistry";
import { getDeploymentChain, readDeploymentArgs } from "../utils";

/**
 * Upgrades the BondingRegistry contract implementation and saves the deployment arguments
 * This keeps the same proxy address, only updates the implementation
 */
export const upgradeBondingRegistry = async () => {
  const { ethers } = await hre.network.connect();
  const [signer] = await ethers.getSigners();
  const signerAddress = await signer.getAddress();
  const chain = getDeploymentChain(hre);
  console.log("Signer:", signerAddress);

  const preDeployedArgs = readDeploymentArgs("BondingRegistry", chain);
  if (!preDeployedArgs?.address) {
    throw new Error(
      "BondingRegistry proxy not found. Deploy first before upgrading.",
    );
  }

  if (!preDeployedArgs?.proxyRecords?.implementationAddress) {
    throw new Error(
      "Existing deployment is not proxy-based. Cannot upgrade non-proxy deployments.",
    );
  }

  console.log(
    "BondingRegistry Proxy Address (from deployments):",
    preDeployedArgs.address,
  );

  const code = await ethers.provider.getCode(preDeployedArgs.address);
  if (code === "0x") {
    throw new Error(
      `No contract found at proxy address ${preDeployedArgs.address}`,
    );
  }
  console.log("Proxy contract exists on-chain");

  const { bondingRegistry, implementationAddress } =
    await upgradeAndSaveBondingRegistry({
      ownerAddress: signerAddress,
      hre,
    });

  const bondingRegistryAddress = await bondingRegistry.getAddress();

  console.log(`
    ============================================
    Upgrade Complete!
    ============================================
    Proxy Address: ${bondingRegistryAddress}
    New Implementation: ${implementationAddress}
    ============================================
  `);
};

upgradeBondingRegistry().catch((error) => {
  console.error(error);
  process.exit(1);
});
