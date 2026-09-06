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

type HonkLibrary = "ZKTranscriptLib" | "RelationsLib";

const normalizeArtifactFqn = (fqn: string): string =>
  fqn
    .replace(/^project\//, "")
    .replace(/^npm\/@interfold\/contracts@[^/]+\//, "@interfold/contracts/");

const getContractFqn = async (
  hre: HardhatRuntimeEnvironment,
  contractName: string,
): Promise<string> => {
  const candidates = Array.from(
    await hre.artifacts.getAllFullyQualifiedNames(),
  ).filter(
    (fqn) =>
      fqn.endsWith(`/${contractName}.sol:${contractName}`) &&
      !fqn.includes("/.benchmark/"),
  );
  if (candidates.length !== 1) {
    throw new Error(
      `Expected one generated artifact for ${contractName}, found ${candidates.length}.`,
    );
  }
  return normalizeArtifactFqn(candidates[0]);
};

const getLibraryLinkFqn = async (
  hre: HardhatRuntimeEnvironment,
  contractName: string,
  libraryName: HonkLibrary,
): Promise<string> => {
  const contractFqn = await getContractFqn(hre, contractName);
  const artifact = await hre.artifacts.readArtifact(contractFqn);
  const source = Object.entries(artifact.linkReferences).find(([, libraries]) =>
    Object.prototype.hasOwnProperty.call(libraries, libraryName),
  )?.[0];
  if (!source) {
    throw new Error(
      `Missing ${libraryName} link reference in ${contractName} artifact.`,
    );
  }
  return `${source}:${libraryName}`;
};

const getLibraryArtifactFqn = async (
  hre: HardhatRuntimeEnvironment,
  contractName: string,
  libraryName: HonkLibrary,
): Promise<string> =>
  normalizeArtifactFqn(await getLibraryLinkFqn(hre, contractName, libraryName));

const getArtifactBytecodeHash = async (
  hre: HardhatRuntimeEnvironment,
  contractName: string,
): Promise<string> => {
  const { ethers } = await hre.network.connect();
  const artifact = await hre.artifacts.readArtifact(contractName);
  let bytecode = artifact.bytecode;
  for (const references of Object.values(artifact.linkReferences)) {
    for (const locations of Object.values(references)) {
      for (const { start, length } of locations) {
        const offset = 2 + start * 2;
        bytecode = `${bytecode.slice(0, offset)}${"0".repeat(length * 2)}${bytecode.slice(offset + length * 2)}`;
      }
    }
  }
  return ethers.keccak256(bytecode);
};

const getVerifierBytecodeHash = async (
  hre: HardhatRuntimeEnvironment,
  contractName: string,
): Promise<string> => {
  const { ethers } = await hre.network.connect();
  const contractFqn = await getContractFqn(hre, contractName);
  const dependencyFqns = await Promise.all(
    (["ZKTranscriptLib", "RelationsLib"] as const).map((libraryName) =>
      getLibraryArtifactFqn(hre, contractName, libraryName),
    ),
  );
  const hashes = await Promise.all([
    getArtifactBytecodeHash(hre, contractFqn),
    ...dependencyFqns.map((fqn) => getArtifactBytecodeHash(hre, fqn)),
  ]);
  return ethers.keccak256(ethers.concat(hashes));
};

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
 * (excluding BfvDecryptionVerifier which lives in bfv/).
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
 * Deploys a library required by BB-generated verifiers.
 * Reuses existing deployment if already deployed on the chain.
 *
 * Uses a fully-qualified name (FQN) because Hardhat has multiple ZKTranscriptLib
 * artifacts (one per verifier .sol file). All are identical; we pick one.
 */
const deployHonkLibrary = async (
  hre: HardhatRuntimeEnvironment,
  chain: string,
  /** Verifier contract whose .sol file contains the library; used to form FQN */
  referenceContract: string,
  libraryName: HonkLibrary,
): Promise<string> => {
  const libFQN = await getLibraryArtifactFqn(
    hre,
    referenceContract,
    libraryName,
  );
  const bytecodeHash = await getArtifactBytecodeHash(hre, libFQN);

  // Check if library is already deployed
  const existing = readDeploymentArgs(libraryName, chain);
  if (existing?.address && existing.bytecodeHash === bytecodeHash) {
    console.log(`   ${libraryName} already deployed at ${existing.address}`);
    return existing.address;
  }

  // Use an FQN to disambiguate duplicate library artifacts.
  console.log(`   Deploying ${libraryName}...`);
  const { ethers } = await hre.network.connect();
  const factory = await ethers.getContractFactory(libFQN);
  const contract = await factory.deploy();
  await contract.waitForDeployment();

  const address = await contract.getAddress();
  const blockNumber = await ethers.provider.getBlockNumber();

  storeDeploymentArgs(
    { blockNumber, address, bytecodeHash },
    libraryName,
    chain,
  );

  console.log(`   ${libraryName} deployed to: ${address}`);
  return address;
};

/**
 * Deploys a single verifier contract and saves the deployment record.
 * BB-generated verifiers require their generated libraries to be linked.
 * Skips deployment if the contract is already deployed on the target chain.
 *
 * Note: The library FQN (fully-qualified name) uses the pattern:
 * "contracts/verifiers/bfv/honk/<ContractName>.sol:ZKTranscriptLib"
 * If you get linking errors, check the contract's compiled artifact for the exact FQN.
 */
export const deployAndSaveVerifier = async (
  contractName: string,
  hre: HardhatRuntimeEnvironment,
  libraryAddresses: {
    zkTranscriptLibAddress: string;
    relationsLibAddress: string;
  },
): Promise<{ address: string }> => {
  const { ethers } = await hre.network.connect();
  const chain = getDeploymentChain(hre);
  const contractFqn = await getContractFqn(hre, contractName);
  const bytecodeHash = await getVerifierBytecodeHash(hre, contractName);

  // Check if already deployed
  const existing = readDeploymentArgs(contractName, chain);
  if (existing?.address && existing.bytecodeHash === bytecodeHash) {
    console.log(`   ${contractName} already deployed at ${existing.address}`);
    return { address: existing.address };
  }

  // Link generated libraries. Keys must match the artifact link references.
  const linkedLibraries = {
    [await getLibraryLinkFqn(hre, contractName, "ZKTranscriptLib")]:
      libraryAddresses.zkTranscriptLibAddress,
    [await getLibraryLinkFqn(hre, contractName, "RelationsLib")]:
      libraryAddresses.relationsLibAddress,
  };

  // Deploy the verifier contract with linked library
  const factory = await ethers.getContractFactory(contractFqn, {
    libraries: linkedLibraries,
  });
  const contract = await factory.deploy();
  await contract.waitForDeployment();

  const address = await contract.getAddress();
  const blockNumber = await ethers.provider.getBlockNumber();

  storeDeploymentArgs(
    {
      blockNumber,
      address,
      bytecodeHash,
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
/**
 * Deploys the two shared Honk libraries and ONE named generated verifier,
 * linked against them. Use when a caller needs a specific circuit verifier
 * without the full `deployAndSaveAllVerifiers` sweep — the CKKS committee-key
 * and decryption verifiers need theirs on the mock demo stacks, where ZK
 * verification (and therefore the sweep) is off.
 */
export const deployAndSaveSingleVerifier = async (
  contractName: string,
  hre: HardhatRuntimeEnvironment,
): Promise<{ address: string }> => {
  const chain = getDeploymentChain(hre);
  const zkTranscriptLibAddress = await deployHonkLibrary(
    hre,
    chain,
    contractName,
    "ZKTranscriptLib",
  );
  const relationsLibAddress = await deployHonkLibrary(
    hre,
    chain,
    contractName,
    "RelationsLib",
  );
  return deployAndSaveVerifier(contractName, hre, {
    zkTranscriptLibAddress,
    relationsLibAddress,
  });
};

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

  const referenceContract = contractNames[0];
  const sharedLibraryHashes = new Map<HonkLibrary, string>();
  for (const libraryName of ["ZKTranscriptLib", "RelationsLib"] as const) {
    const libraryFqn = await getLibraryArtifactFqn(
      hre,
      referenceContract,
      libraryName,
    );
    sharedLibraryHashes.set(
      libraryName,
      await getArtifactBytecodeHash(hre, libraryFqn),
    );
  }

  for (const contractName of contractNames.slice(1)) {
    for (const libraryName of ["ZKTranscriptLib", "RelationsLib"] as const) {
      const libraryFqn = await getLibraryArtifactFqn(
        hre,
        contractName,
        libraryName,
      );
      const hash = await getArtifactBytecodeHash(hre, libraryFqn);
      const referenceHash = sharedLibraryHashes.get(libraryName);
      if (hash !== referenceHash) {
        throw new Error(
          `${libraryName} bytecode differs between ${referenceContract} (${referenceHash}) and ${contractName} (${hash}); refusing shared deployment.`,
        );
      }
    }
  }

  // Deploy each generated library once and reuse it for all verifiers.
  const zkTranscriptLibAddress = await deployHonkLibrary(
    hre,
    chain,
    referenceContract,
    "ZKTranscriptLib",
  );
  const relationsLibAddress = await deployHonkLibrary(
    hre,
    chain,
    referenceContract,
    "RelationsLib",
  );

  const deployments: VerifierDeployments = {};

  for (const name of contractNames) {
    const { address } = await deployAndSaveVerifier(name, hre, {
      zkTranscriptLibAddress,
      relationsLibAddress,
    });
    deployments[name] = address;
  }

  return deployments;
};
