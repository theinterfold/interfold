// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import hre from "hardhat";

import { deployAndSaveMockComputeProvider } from "./deployAndSave/mockComputeProvider";
import { deployAndSaveMockDecryptionVerifier } from "./deployAndSave/mockDecryptionVerifier";
import { deployAndSaveMockPkVerifier } from "./deployAndSave/mockPkVerifier";
import { deployAndSaveMockProgram } from "./deployAndSave/mockProgram";

export interface MockDeployments {
  computeProviderAddress: string;
  /** Mock verifier addresses; deployment args are always saved for tooling (e.g. `committee:new` default `computeProviderParams`). */
  decryptionVerifierAddress: string;
  pkVerifierAddress: string;
  e3ProgramAddress: string;
}

/**
 * Deploys the mock contracts and returns the addresses.
 * Mock decryption/pk verifiers are always deployed and saved so deployment artifacts exist for tasks that derive
 * default `computeProviderParams` (see `tasks/interfold.ts`). When ZK verification is enabled, `deployInterfold` still
 * registers the real BFV verifiers on Interfold instead of these mocks.
 */
export const deployMocks = async (): Promise<MockDeployments> => {
  console.log("Deploying Compute Provider");
  const { computeProvider } = await deployAndSaveMockComputeProvider(hre);

  const computeProviderAddress = await computeProvider.getAddress();

  console.log("Deploying Mock Decryption Verifier");
  const { decryptionVerifier } = await deployAndSaveMockDecryptionVerifier(hre);
  const decryptionVerifierAddress = await decryptionVerifier.getAddress();
  console.log("Deploying Mock Pk Verifier");
  const { pkVerifier } = await deployAndSaveMockPkVerifier(hre);
  const pkVerifierAddress = await pkVerifier.getAddress();

  console.log("Deploying E3 Program");
  const { e3Program } = await deployAndSaveMockProgram({
    hre,
  });

  const e3ProgramAddress = await e3Program.getAddress();

  console.log(`
        MockDeployments:
        ----------------------------------------------------------------------
        MockComputeProvider:${computeProviderAddress}
        MockDecryptionVerifier:${decryptionVerifierAddress}
        MockPkVerifier:${pkVerifierAddress}
        MockE3Program:${e3ProgramAddress}
        `);

  return {
    computeProviderAddress,
    decryptionVerifierAddress,
    pkVerifierAddress,
    e3ProgramAddress,
  };
};
