// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import type { HardhatRuntimeEnvironment } from "hardhat/types/hre";

import { readDeploymentArgs, storeDeploymentArgs } from "../utils";
import { deployAndSaveSingleVerifier } from "./verifiers";

/**
 * CKKS param sets the demo apps run on, mapped to the `pk_generation_ckks_ps<N>`
 * Honk verifier that proves a party's pk share for that set.
 *
 *   ps0 — canonical dev CKKS E3s
 *   ps2 — examples/ckks-auction
 *   ps3 — examples/ckks-salary-survey
 *   ps4 — examples/ckks-credit-scoring
 *   ps5 — examples/ckks-matching, examples/ckks-treasury-risk,
 *         examples/ckks-federated-averaging (shared coefficient preset)
 *
 * ONE `CkksPkVerifier` covers them all: `Interfold` keys verifiers by encryption
 * scheme only, so the contract dispatches on `interfold.getE3(e3Id).paramSet`.
 */
export const CKKS_PK_CIRCUIT_VERIFIERS: ReadonlyArray<
  readonly [paramSet: number, contractName: string]
> = [
  [0, "PkGenerationCkksPs0Verifier"],
  [2, "PkGenerationCkksPs2Verifier"],
  [3, "PkGenerationCkksPs3Verifier"],
  [4, "PkGenerationCkksPs4Verifier"],
  [5, "PkGenerationCkksPs5Verifier"],
];

export const deployAndSaveCkksPkVerifier = async (
  hre: HardhatRuntimeEnvironment,
  interfoldAddress: string,
  committeeSize: number,
): Promise<{ address: string }> => {
  const { ethers } = await hre.network.connect();
  const chain = hre.globalOptions.network ?? "localhost";

  const existing = readDeploymentArgs("CkksPkVerifier", chain);
  if (existing?.address) {
    console.log(`   CkksPkVerifier already deployed at ${existing.address}`);
    return { address: existing.address };
  }

  const paramSets: number[] = [];
  const circuitVerifiers: string[] = [];
  for (const [paramSet, contractName] of CKKS_PK_CIRCUIT_VERIFIERS) {
    let args = readDeploymentArgs(contractName, chain);
    if (!args?.address) {
      // The demo stacks run the mock path, where `deployAndSaveAllVerifiers`
      // (every generated Honk verifier) is skipped. The CKKS committee-key
      // check still needs its per-param-set circuit verifiers, so deploy the
      // few we need on demand instead of requiring full ZK verification.
      console.log(`   Deploying ${contractName} (CKKS committee-key circuit)`);
      const { address } = await deployAndSaveSingleVerifier(contractName, hre);
      args = { address };
    }
    paramSets.push(paramSet);
    circuitVerifiers.push(args.address);
  }

  const factory = await ethers.getContractFactory("CkksPkVerifier");
  const verifier = await factory.deploy(
    interfoldAddress,
    paramSets,
    circuitVerifiers,
    committeeSize,
  );
  await verifier.waitForDeployment();
  const address = await verifier.getAddress();

  storeDeploymentArgs(
    { blockNumber: await ethers.provider.getBlockNumber(), address },
    "CkksPkVerifier",
    chain,
  );
  console.log(`   CkksPkVerifier deployed to: ${address}`);
  return { address };
};
