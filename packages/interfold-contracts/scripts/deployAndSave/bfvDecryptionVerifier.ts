// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import type { HardhatRuntimeEnvironment } from "hardhat/types/hre";

import {
  BfvDecryptionVerifier,
  BfvDecryptionVerifier__factory as BfvDecryptionVerifierFactory,
} from "../../types";
import {
  BFV_DECRYPTION_SUB_CIRCUIT_VK_HASH_PATHS,
  BFV_THRESHOLD_T,
  assertBfvDecryptionVerifierSubCircuitVkHashes,
  readDeploymentArgs,
  readVkRecursiveHash,
  storeDeploymentArgs,
} from "../utils";

export const deployAndSaveBfvDecryptionVerifier = async (
  hre: HardhatRuntimeEnvironment,
): Promise<{
  bfvDecryptionVerifier: BfvDecryptionVerifier;
}> => {
  const { ethers } = await hre.network.connect();
  const [signer] = await ethers.getSigners();
  const chain = hre.globalOptions.network ?? "localhost";

  const circuitVerifierArgs = readDeploymentArgs(
    "DecryptionAggregatorVerifier",
    chain,
  );
  if (!circuitVerifierArgs?.address) {
    throw new Error(
      "DecryptionAggregatorVerifier must be deployed first. " +
        "Run deployAndSaveAllVerifiers or deploy verifiers.",
    );
  }

  const existing = readDeploymentArgs("BfvDecryptionVerifier", chain);
  if (existing?.address) {
    console.log(
      `   BfvDecryptionVerifier already deployed at ${existing.address}`,
    );
    const bfvDecryptionVerifier = BfvDecryptionVerifierFactory.connect(
      existing.address,
      signer,
    );
    await assertBfvDecryptionVerifierSubCircuitVkHashes(
      bfvDecryptionVerifier,
      existing.address,
    );
    return { bfvDecryptionVerifier };
  }

  const expectedC6FoldKeyHash = readVkRecursiveHash(
    BFV_DECRYPTION_SUB_CIRCUIT_VK_HASH_PATHS.c6Fold,
  );
  const expectedC7KeyHash = readVkRecursiveHash(
    BFV_DECRYPTION_SUB_CIRCUIT_VK_HASH_PATHS.c7,
  );

  const bfvDecryptionVerifierFactory = await ethers.getContractFactory(
    "BfvDecryptionVerifier",
  );
  const bfvDecryptionVerifier = await bfvDecryptionVerifierFactory.deploy(
    circuitVerifierArgs.address,
    expectedC6FoldKeyHash,
    expectedC7KeyHash,
    BFV_THRESHOLD_T,
  );

  await bfvDecryptionVerifier.waitForDeployment();
  const bfvDecryptionVerifierAddress = await bfvDecryptionVerifier.getAddress();

  const blockNumber = await ethers.provider.getBlockNumber();

  storeDeploymentArgs(
    {
      blockNumber,
      address: bfvDecryptionVerifierAddress,
    },
    "BfvDecryptionVerifier",
    chain,
  );

  console.log(
    `   BfvDecryptionVerifier deployed to: ${bfvDecryptionVerifierAddress}`,
  );

  const bfvDecryptionVerifierContract = BfvDecryptionVerifierFactory.connect(
    bfvDecryptionVerifierAddress,
    signer,
  );

  return { bfvDecryptionVerifier: bfvDecryptionVerifierContract };
};
