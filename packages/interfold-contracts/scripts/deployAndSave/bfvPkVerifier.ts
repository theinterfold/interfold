// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import type { HardhatRuntimeEnvironment } from "hardhat/types/hre";

import {
  BfvPkVerifier,
  BfvPkVerifier__factory as BfvPkVerifierFactory,
} from "../../types";
import {
  BFV_DKG_H,
  BFV_PK_SUB_CIRCUIT_VK_HASH_PATHS,
  assertBfvPkVerifierSubCircuitVkHashes,
  readDeploymentArgs,
  readVkRecursiveHash,
  storeDeploymentArgs,
} from "../utils";

export const deployAndSaveBfvPkVerifier = async (
  hre: HardhatRuntimeEnvironment,
): Promise<{
  bfvPkVerifier: BfvPkVerifier;
}> => {
  const { ethers } = await hre.network.connect();
  const [signer] = await ethers.getSigners();
  const chain = hre.globalOptions.network ?? "localhost";

  const circuitVerifierArgs = readDeploymentArgs(
    "DkgAggregatorVerifier",
    chain,
  );
  if (!circuitVerifierArgs?.address) {
    throw new Error(
      "DkgAggregatorVerifier must be deployed first. " +
        "Run deployAndSaveAllVerifiers or deploy verifiers.",
    );
  }

  const existing = readDeploymentArgs("BfvPkVerifier", chain);
  if (existing?.address) {
    console.log(`   BfvPkVerifier already deployed at ${existing.address}`);
    const bfvPkVerifier = BfvPkVerifierFactory.connect(
      existing.address,
      signer,
    );
    await assertBfvPkVerifierSubCircuitVkHashes(
      bfvPkVerifier,
      existing.address,
    );
    return { bfvPkVerifier };
  }

  const expectedNodesFoldKeyHash = readVkRecursiveHash(
    BFV_PK_SUB_CIRCUIT_VK_HASH_PATHS.nodesFold,
  );
  const expectedC5KeyHash = readVkRecursiveHash(
    BFV_PK_SUB_CIRCUIT_VK_HASH_PATHS.c5,
  );

  const bfvPkVerifierFactory = await ethers.getContractFactory("BfvPkVerifier");
  const bfvPkVerifier = await bfvPkVerifierFactory.deploy(
    circuitVerifierArgs.address,
    expectedNodesFoldKeyHash,
    expectedC5KeyHash,
    BFV_DKG_H,
  );

  await bfvPkVerifier.waitForDeployment();
  const bfvPkVerifierAddress = await bfvPkVerifier.getAddress();

  const blockNumber = await ethers.provider.getBlockNumber();

  storeDeploymentArgs(
    {
      blockNumber,
      address: bfvPkVerifierAddress,
    },
    "BfvPkVerifier",
    chain,
  );

  console.log(`   BfvPkVerifier deployed to: ${bfvPkVerifierAddress}`);

  const bfvPkVerifierContract = BfvPkVerifierFactory.connect(
    bfvPkVerifierAddress,
    signer,
  );

  return { bfvPkVerifier: bfvPkVerifierContract };
};
