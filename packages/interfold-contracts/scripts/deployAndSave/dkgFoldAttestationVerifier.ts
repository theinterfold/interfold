// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import type { HardhatRuntimeEnvironment } from "hardhat/types/hre";

import {
  DkgFoldAttestationVerifier,
  DkgFoldAttestationVerifier__factory as DkgFoldAttestationVerifierFactory,
} from "../../types";
import {
  getDeploymentChain,
  readDeploymentArgs,
  storeDeploymentArgs,
} from "../utils";

export const deployAndSaveDkgFoldAttestationVerifier = async (
  hre: HardhatRuntimeEnvironment,
): Promise<{
  dkgFoldAttestationVerifier: DkgFoldAttestationVerifier;
}> => {
  const { ethers } = await hre.network.connect();
  const [signer] = await ethers.getSigners();
  const chain = getDeploymentChain(hre);

  const existing = readDeploymentArgs("DkgFoldAttestationVerifier", chain);
  if (existing?.address) {
    console.log(
      `   DkgFoldAttestationVerifier already deployed at ${existing.address}`,
    );
    const dkgFoldAttestationVerifier =
      DkgFoldAttestationVerifierFactory.connect(existing.address, signer);
    return { dkgFoldAttestationVerifier };
  }

  const dkgFoldAttestationVerifier =
    await new DkgFoldAttestationVerifierFactory(signer).deploy();
  await dkgFoldAttestationVerifier.waitForDeployment();
  const address = await dkgFoldAttestationVerifier.getAddress();
  const blockNumber = await ethers.provider.getBlockNumber();

  storeDeploymentArgs(
    { address, blockNumber },
    "DkgFoldAttestationVerifier",
    chain,
  );
  console.log(`   DkgFoldAttestationVerifier deployed to: ${address}`);

  return { dkgFoldAttestationVerifier };
};
