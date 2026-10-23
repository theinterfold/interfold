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
  BFV_THRESHOLD_T,
  assertBfvDecryptionVerifierSubCircuitVkHashes,
  bfvMessageCoeffsCount,
  getBfvDecryptionSubCircuitVkHashPaths,
  localBfvParamSet,
  readDeploymentArgs,
  readVkRecursiveHash,
  storeDeploymentArgs,
} from "../utils";

export const deployAndSaveBfvDecryptionVerifier = async (
  hre: HardhatRuntimeEnvironment,
  ciphernodeRegistryAddress: string,
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
    const [onChainCircuitVerifier, onChainRegistry] = await Promise.all([
      bfvDecryptionVerifier.circuitVerifier(),
      bfvDecryptionVerifier.ciphernodeRegistry(),
    ]);
    if (
      onChainCircuitVerifier.toLowerCase() !==
        circuitVerifierArgs.address.toLowerCase() ||
      onChainRegistry.toLowerCase() !== ciphernodeRegistryAddress.toLowerCase()
    ) {
      throw new Error(
        `BfvDecryptionVerifier at ${existing.address} has stale verifier dependencies. ` +
          `Expected circuitVerifier=${circuitVerifierArgs.address}, ciphernodeRegistry=${ciphernodeRegistryAddress}. ` +
          "Redeploy after the verifier dependencies change.",
      );
    }
    await assertBfvDecryptionVerifierSubCircuitVkHashes(
      bfvDecryptionVerifier,
      existing.address,
    );
    return { bfvDecryptionVerifier };
  }

  const expectedC6FoldKeyHash = readVkRecursiveHash(
    getBfvDecryptionSubCircuitVkHashPaths().c6Fold,
  );
  const expectedC7KeyHash = readVkRecursiveHash(
    getBfvDecryptionSubCircuitVkHashPaths().c7,
  );

  const bfvDecryptionVerifierFactory = await ethers.getContractFactory(
    "BfvDecryptionVerifier",
  );
  const bfvDecryptionVerifier = await bfvDecryptionVerifierFactory.deploy(
    circuitVerifierArgs.address,
    ciphernodeRegistryAddress,
    expectedC6FoldKeyHash,
    expectedC7KeyHash,
    BFV_THRESHOLD_T,
    bfvMessageCoeffsCount(localBfvParamSet()),
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
