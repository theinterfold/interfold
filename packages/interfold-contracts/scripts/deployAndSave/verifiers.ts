// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import fs from "fs";
import type { HardhatRuntimeEnvironment } from "hardhat/types/hre";
import path from "path";
import { fileURLToPath } from "url";

import {
  getDeploymentChain,
  readDeploymentArgs,
  storeDeploymentArgs,
} from "../utils";

const BFV_HONK_VERIFIER_DIR = "contracts/verifiers/bfv/honk";
const NPM_HONK_SOURCE_PREFIX =
  "@interfold/contracts/contracts/verifiers/bfv/honk";
// Hardhat uses npm/package@version/ for library linking when built from npm deps (pnpm workspace: @local)
const NPM_HONK_LIBRARY_LINK_PREFIX =
  "npm/@interfold/contracts@local/contracts/verifiers/bfv/honk";

/** True when Hardhat artifacts use npm paths (consuming project like CRISP). */
const isNpmArtifactContext = (): boolean =>
  !fs.existsSync(path.join(process.cwd(), BFV_HONK_VERIFIER_DIR));

/** Package root of interfold-contracts. Used when script runs from another project (e.g. CRISP). */
const getInterfoldContractsRoot = (): string => {
  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  // scripts/deployAndSave -> package root (2 levels up)
  // dist/scripts/deployAndSave -> package root (3 levels up)
  for (const honkDir of [
    path.join(__dirname, "..", "..", BFV_HONK_VERIFIER_DIR),
    path.join(__dirname, "..", "..", "..", BFV_HONK_VERIFIER_DIR),
  ]) {
    if (fs.existsSync(honkDir)) {
      return path.join(honkDir, "..", "..", "..", ".."); // honk -> bfv -> verifiers -> contracts -> root
    }
  }
  return path.join(__dirname, "..", "..");
};

/**
 * Discovers Honk/BB verifier contracts in contracts/verifiers/bfv/honk/
 * (excluding BfvDecryptionVerifier which lives in bfv/ and does not use ZKTranscriptLib).
 * Uses interfold-contracts package root so discovery works when run from consuming projects (e.g. CRISP).
 */
export const discoverVerifierContracts = (): string[] => {
  const honkDir = path.join(getInterfoldContractsRoot(), BFV_HONK_VERIFIER_DIR);
  if (!fs.existsSync(honkDir)) {
    return [];
  }

  return fs
    .readdirSync(honkDir)
    .filter((f) => f.endsWith(".sol"))
    .map((f) => f.replace(".sol", ""));
};

/**
 * Deploys ZKTranscriptLib library required by BB-generated verifiers.
 * Reuses existing deployment if already deployed on the chain.
 *
 * Uses a fully-qualified name (FQN) because Hardhat has multiple ZKTranscriptLib
 * artifacts (one per verifier .sol file). All are identical; we pick one.
 */
const deployZKTranscriptLib = async (
  hre: HardhatRuntimeEnvironment,
  chain: string,
  /** Verifier contract whose .sol file contains ZKTranscriptLib; used to form FQN */
  referenceContract: string,
): Promise<string> => {
  const libName = "ZKTranscriptLib";

  // Check if library is already deployed
  const existing = readDeploymentArgs(libName, chain);
  if (existing?.address) {
    console.log(`   ${libName} already deployed at ${existing.address}`);
    return existing.address;
  }

  // Deploy the library — use FQN to disambiguate multiple ZKTranscriptLib artifacts.
  // Npm context (CRISP): @interfold/contracts/contracts/verifiers/bfv/honk/X.sol
  // Project context (interfold-contracts): contracts/verifiers/bfv/honk/X.sol
  const libFQN = isNpmArtifactContext()
    ? `${NPM_HONK_SOURCE_PREFIX}/${referenceContract}.sol:ZKTranscriptLib`
    : `${BFV_HONK_VERIFIER_DIR}/${referenceContract}.sol:ZKTranscriptLib`;
  console.log(`   Deploying ${libName}...`);
  const { ethers } = await hre.network.connect();
  const factory = await ethers.getContractFactory(libFQN);
  const contract = await factory.deploy();
  await contract.waitForDeployment();

  const address = await contract.getAddress();
  const blockNumber = await ethers.provider.getBlockNumber();

  storeDeploymentArgs({ blockNumber, address }, libName, chain);

  console.log(`   ${libName} deployed to: ${address}`);
  return address;
};

/**
 * Deploys a single verifier contract and saves the deployment record.
 * BB-generated verifiers require ZKTranscriptLib to be linked.
 * Skips deployment if the contract is already deployed on the target chain.
 *
 * Note: The library FQN (fully-qualified name) uses the pattern:
 * "contracts/verifiers/bfv/honk/<ContractName>.sol:ZKTranscriptLib"
 * If you get linking errors, check the contract's compiled artifact for the exact FQN.
 */
export const deployAndSaveVerifier = async (
  contractName: string,
  hre: HardhatRuntimeEnvironment,
  zkTranscriptLibAddress: string,
): Promise<{ address: string }> => {
  const { ethers } = await hre.network.connect();
  const chain = getDeploymentChain(hre);

  // Check if already deployed
  const existing = readDeploymentArgs(contractName, chain);
  if (existing?.address) {
    console.log(`   ${contractName} already deployed at ${existing.address}`);
    return { address: existing.address };
  }

  // Link ZKTranscriptLib — key must match Hardhat's expected format for library linking.
  // Npm context: npm/@interfold/contracts@local/contracts/... (pnpm workspace)
  // Project context: project/contracts/...
  const libraryFQN = isNpmArtifactContext()
    ? `${NPM_HONK_LIBRARY_LINK_PREFIX}/${contractName}.sol:ZKTranscriptLib`
    : `project/${BFV_HONK_VERIFIER_DIR}/${contractName}.sol:ZKTranscriptLib`;
  const libraries = {
    [libraryFQN]: zkTranscriptLibAddress,
  };

  // Deploy the verifier contract with linked library
  const factory = await ethers.getContractFactory(contractName, { libraries });
  const contract = await factory.deploy();
  await contract.waitForDeployment();

  const address = await contract.getAddress();
  const blockNumber = await ethers.provider.getBlockNumber();

  storeDeploymentArgs(
    {
      blockNumber,
      address,
    },
    contractName,
    chain,
  );

  console.log(`   ${contractName} deployed to: ${address}`);
  return { address };
};

export interface VerifierDeployments {
  [contractName: string]: string; // contract name → deployed address
}

/**
 * Deploys all Honk verifier contracts found in contracts/verifiers/bfv/honk/.
 * Skips any that are already deployed on the target chain.
 *
 * @returns A mapping of contract names to their deployed addresses.
 */
export const deployAndSaveAllVerifiers = async (
  hre: HardhatRuntimeEnvironment,
): Promise<VerifierDeployments> => {
  const contractNames = discoverVerifierContracts();
  const chain = getDeploymentChain(hre);
  console.log(`   Deploying to network: ${chain}`);

  if (contractNames.length === 0) {
    console.log(
      "   No verifier contracts found in contracts/verifiers/bfv/honk/. Skipping.",
    );
    return {};
  }

  console.log(`   Found ${contractNames.length} verifier contract(s)`);

  // Deploy ZKTranscriptLib once, reused by all verifiers
  const zkTranscriptLibAddress = await deployZKTranscriptLib(
    hre,
    chain,
    contractNames[0],
  );

  const deployments: VerifierDeployments = {};

  for (const name of contractNames) {
    const { address } = await deployAndSaveVerifier(
      name,
      hre,
      zkTranscriptLibAddress,
    );
    deployments[name] = address;
  }

  return deployments;
};
