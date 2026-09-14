// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import type { HardhatRuntimeEnvironment } from "hardhat/types/hre";

import {
  BfvPkVerifier,
  BfvPkVerifier__factory as BfvPkVerifierFactory,
  BfvPkVerifierV2,
  BfvPkVerifierV2__factory as BfvPkVerifierV2Factory,
} from "../../types";
import { currentNodeRelease } from "../protocol/nodeRelease";
import {
  BFV_DKG_H,
  assertBfvPkVerifierSubCircuitVkHashes,
  assertBfvPkVerifierV2VkHashes,
  getBfvPkSubCircuitVkHashPaths,
  getBfvPkVkBindingHashPaths,
  getBfvV2SubCircuitVkHashPaths,
  getBfvV2VkBindingHashPaths,
  readDeploymentArgs,
  readVkRecursiveHash,
  storeDeploymentArgs,
} from "../utils";
import { deployAndSaveVerifier } from "./verifiers";

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
  const expectedVkBinding = getBfvPkVkBindingHashPaths().map((filePath) =>
    readVkRecursiveHash(filePath),
  );

  const bfvPkVerifierFactory = await ethers.getContractFactory("BfvPkVerifier");
  const bfvPkVerifier = await bfvPkVerifierFactory.deploy(
    circuitVerifierArgs.address,
    expectedNodesFoldKeyHash,
    expectedC5KeyHash,
    expectedSkC2ChunkKeyHash,
    expectedESmC2ChunkKeyHash,
    expectedVkBinding,
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

export const deployAndSaveBfvPkVerifierV2 = async (
  hre: HardhatRuntimeEnvironment,
  ciphernodeRegistryAddress: string,
): Promise<{
  bfvPkVerifierV2: BfvPkVerifierV2;
}> => {
  const { ethers } = await hre.network.connect();
  const [signer] = await ethers.getSigners();
  const chain = hre.globalOptions.network ?? "localhost";

  let circuitVerifierArgs = readDeploymentArgs(
    "DkgAggregatorV2Verifier",
    chain,
  );
  if (!circuitVerifierArgs?.address) {
    const zkTranscriptLib = readDeploymentArgs("ZKTranscriptLib", chain);
    const relationsLib = readDeploymentArgs("RelationsLib", chain);
    if (!zkTranscriptLib?.address || !relationsLib?.address) {
      throw new Error(
        "DkgAggregatorV2Verifier requires deployed Honk libraries. " +
          "Run deployAndSaveAllVerifiers or deploy verifiers.",
      );
    }
    const deployed = await deployAndSaveVerifier(
      "DkgAggregatorV2Verifier",
      hre,
      {
        zkTranscriptLibAddress: zkTranscriptLib.address,
        relationsLibAddress: relationsLib.address,
      },
    );
    circuitVerifierArgs = { address: deployed.address };
  }

  const expectedNodesFoldKeyHash = readVkRecursiveHash(
    getBfvV2SubCircuitVkHashPaths().nodesFold,
  );
  const pkPaths = getBfvPkSubCircuitVkHashPaths();
  const expectedC5KeyHash = readVkRecursiveHash(pkPaths.c5);
  const expectedSkC2ChunkKeyHash = readVkRecursiveHash(pkPaths.skC2Chunk);
  const expectedESmC2ChunkKeyHash = readVkRecursiveHash(pkPaths.esmC2Chunk);
  const expectedLegacyVkBinding = getBfvPkVkBindingHashPaths().map((filePath) =>
    readVkRecursiveHash(filePath),
  );
  const expectedV2VkBinding = getBfvV2VkBindingHashPaths().map((filePath) =>
    readVkRecursiveHash(filePath),
  );

  const existing = readDeploymentArgs("BfvPkVerifierV2", chain);
  if (existing?.address) {
    console.log(`   BfvPkVerifierV2 already deployed at ${existing.address}`);
    const bfvPkVerifierV2 = BfvPkVerifierV2Factory.connect(
      existing.address,
      signer,
    );
    const [onChainCircuitVerifier, onChainRegistry, onChainProtocolVersion] =
      await Promise.all([
        bfvPkVerifierV2.circuitVerifier(),
        bfvPkVerifierV2.ciphernodeRegistry(),
        bfvPkVerifierV2.getFunction("LBFV_PROTOCOL_VERSION").staticCall(),
      ]);
    const expectedProtocolVersion = BigInt(
      currentNodeRelease().protocolVersion,
    );
    if (
      onChainCircuitVerifier.toLowerCase() !==
        circuitVerifierArgs.address.toLowerCase() ||
      onChainRegistry.toLowerCase() !==
        ciphernodeRegistryAddress.toLowerCase() ||
      onChainProtocolVersion !== expectedProtocolVersion
    ) {
      throw new Error(
        `BfvPkVerifierV2 at ${existing.address} has stale verifier dependencies. ` +
          `Expected circuitVerifier=${circuitVerifierArgs.address}, ciphernodeRegistry=${ciphernodeRegistryAddress}, ` +
          `protocolVersion=${expectedProtocolVersion}. ` +
          "Redeploy after the verifier dependencies change.",
      );
    }
    try {
      await assertBfvPkVerifierV2VkHashes(bfvPkVerifierV2, existing.address);
    } catch (error) {
      throw new Error(
        `BfvPkVerifierV2 at ${existing.address} is incompatible with the current VK-anchor ABI. ` +
          "Redeploy the verifier before reuse.",
        { cause: error },
      );
    }
    return { bfvPkVerifierV2 };
  }

  const bfvPkVerifierV2Factory =
    await ethers.getContractFactory("BfvPkVerifierV2");
  const bfvPkVerifierV2 = await bfvPkVerifierV2Factory.deploy(
    circuitVerifierArgs.address,
    ciphernodeRegistryAddress,
    expectedNodesFoldKeyHash,
    expectedC5KeyHash,
    expectedSkC2ChunkKeyHash,
    expectedESmC2ChunkKeyHash,
    expectedLegacyVkBinding,
    expectedV2VkBinding,
  );

  await bfvPkVerifierV2.waitForDeployment();
  const bfvPkVerifierV2Address = await bfvPkVerifierV2.getAddress();
  const blockNumber = await ethers.provider.getBlockNumber();

  storeDeploymentArgs(
    {
      blockNumber,
      address: bfvPkVerifierV2Address,
    },
    "BfvPkVerifierV2",
    chain,
  );

  console.log(`   BfvPkVerifierV2 deployed to: ${bfvPkVerifierV2Address}`);

  return {
    bfvPkVerifierV2: BfvPkVerifierV2Factory.connect(
      bfvPkVerifierV2Address,
      signer,
    ),
  };
};
