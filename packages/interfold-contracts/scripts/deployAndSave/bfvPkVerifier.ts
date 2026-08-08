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
  assertBfvPkVerifierSubCircuitVkHashes,
  getBfvPkSubCircuitVkHashPaths,
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
    const onChainCircuitVerifier = await bfvPkVerifier.circuitVerifier();
    if (
      onChainCircuitVerifier.toLowerCase() !==
      circuitVerifierArgs.address.toLowerCase()
    ) {
      throw new Error(
        `BfvPkVerifier at ${existing.address} points to ${onChainCircuitVerifier}, expected ${circuitVerifierArgs.address}. ` +
          "Redeploy after the circuit verifier changes.",
      );
    }
    try {
      await assertBfvPkVerifierSubCircuitVkHashes(
        bfvPkVerifier,
        existing.address,
      );
    } catch (error) {
      throw new Error(
        `BfvPkVerifier at ${existing.address} is incompatible with the current VK-anchor ABI. ` +
          "Redeploy the verifier before reuse.",
        { cause: error },
      );
    }
    return { bfvPkVerifier };
  }

  const expectedNodesFoldKeyHash = readVkRecursiveHash(
    getBfvPkSubCircuitVkHashPaths().nodesFold,
  );
  const expectedC5KeyHash = readVkRecursiveHash(
    getBfvPkSubCircuitVkHashPaths().c5,
  );
  const expectedSkC2ChunkKeyHash = readVkRecursiveHash(
    getBfvPkSubCircuitVkHashPaths().skC2Chunk,
  );
  const expectedESmC2ChunkKeyHash = readVkRecursiveHash(
    getBfvPkSubCircuitVkHashPaths().esmC2Chunk,
  );

  const bfvPkVerifierFactory = await ethers.getContractFactory("BfvPkVerifier");
  const bfvPkVerifier = await bfvPkVerifierFactory.deploy(
    circuitVerifierArgs.address,
    expectedNodesFoldKeyHash,
    expectedC5KeyHash,
    expectedSkC2ChunkKeyHash,
    expectedESmC2ChunkKeyHash,
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
