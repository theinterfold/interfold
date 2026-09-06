// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import type { HardhatRuntimeEnvironment } from "hardhat/types/hre";

import { readDeploymentArgs, storeDeploymentArgs } from "../utils";
import { deployAndSaveSingleVerifier } from "./verifiers";

/**
 * CKKS param sets mapped to the `decrypted_shares_aggregation_ckks[_ps<N>]` Honk
 * verifier that proves the threshold reconstruction for that set. ParamSet 0 uses
 * the unsuffixed circuit name.
 *
 * ONE `CkksDecryptionVerifier` covers them all; it dispatches on
 * `interfold.getE3(e3Id).paramSet`.
 */
export const CKKS_DECRYPTION_CIRCUIT_VERIFIERS: ReadonlyArray<
  readonly [paramSet: number, contractName: string]
> = [
  [0, "DecryptedSharesAggregationCkksVerifier"],
  [2, "DecryptedSharesAggregationCkksPs2Verifier"],
  [3, "DecryptedSharesAggregationCkksPs3Verifier"],
  [4, "DecryptedSharesAggregationCkksPs4Verifier"],
  [5, "DecryptedSharesAggregationCkksPs5Verifier"],
];

export const deployAndSaveCkksDecryptionVerifier = async (
  hre: HardhatRuntimeEnvironment,
  interfoldAddress: string,
  threshold: number,
): Promise<{ address: string }> => {
  const { ethers } = await hre.network.connect();
  const chain = hre.globalOptions.network ?? "localhost";

  const existing = readDeploymentArgs("CkksDecryptionVerifier", chain);
  if (existing?.address) {
    console.log(
      `   CkksDecryptionVerifier already deployed at ${existing.address}`,
    );
    return { address: existing.address };
  }

  const paramSets: number[] = [];
  const circuitVerifiers: string[] = [];
  for (const [paramSet, contractName] of CKKS_DECRYPTION_CIRCUIT_VERIFIERS) {
    let args = readDeploymentArgs(contractName, chain);
    if (!args?.address) {
      // Demo stacks run the mock path, where `deployAndSaveAllVerifiers` is
      // skipped; deploy the CKKS decryption circuit verifiers on demand so
      // the decrypted output is still checked by a real Honk proof.
      console.log(`   Deploying ${contractName} (CKKS decryption circuit)`);
      const { address } = await deployAndSaveSingleVerifier(contractName, hre);
      args = { address };
    }
    paramSets.push(paramSet);
    circuitVerifiers.push(args.address);
  }

  const factory = await ethers.getContractFactory("CkksDecryptionVerifier");
  const verifier = await factory.deploy(
    interfoldAddress,
    paramSets,
    circuitVerifiers,
    threshold,
  );
  await verifier.waitForDeployment();
  const address = await verifier.getAddress();

  storeDeploymentArgs(
    { blockNumber: await ethers.provider.getBlockNumber(), address },
    "CkksDecryptionVerifier",
    chain,
  );
  console.log(`   CkksDecryptionVerifier deployed to: ${address}`);
  return { address };
};
