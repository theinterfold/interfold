// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import hre from "hardhat";

import { deployAndSaveCkksAppProgram } from "./deployAndSave/ckksAppProgram";
import { deployAndSaveCkksProgram } from "./deployAndSave/ckksProgram";
import { deployAndSaveMockCiphertextVerifier } from "./deployAndSave/mockCiphertextVerifier";
import { deployAndSaveMockCkksProgram } from "./deployAndSave/mockCkksProgram";
import { deployAndSaveMockComputeProvider } from "./deployAndSave/mockComputeProvider";
import { deployAndSaveMockDecryptionVerifier } from "./deployAndSave/mockDecryptionVerifier";
import { deployAndSaveMockPkVerifier } from "./deployAndSave/mockPkVerifier";
import { deployAndSaveMockProgram } from "./deployAndSave/mockProgram";

export interface MockDeployments {
  computeProviderAddress: string;
  /** Mock verifier addresses; deployment args are always saved for tooling (e.g. `committee:new` default `computeProviderParams`). */
  decryptionVerifierAddress: string;
  ciphertextVerifierAddress: string;
  pkVerifierAddress: string;
  e3ProgramAddress: string;
  /** CKKS E3 program (program address => protocol: binds fhe.rs:CKKS). */
  ckksProgramAddress: string;
  /** Greco-gated CKKS program (canonical dev ParamSet 0 verifiers). */
  ckksVerifiedProgramAddress: string;
  /** Greco-gated CKKS program wired to the ParamSet 3 (statistics) verifiers. */
  ckksVerifiedProgramPs3Address: string;
  ckksSalaryProgramAddress: string;
  ckksAuctionProgramAddress: string;
  /** Three-leg credit-scoring program (ParamSet 4 verifiers). */
  ckksCreditProgramAddress: string;
  /** Five-leg federated-averaging program (ParamSet 5 verifiers). */
  ckksFedAvgProgramAddress: string;
  ckksMatchingProgramAddress: string;
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
  console.log("Deploying Mock Ciphertext Verifier");
  const { ciphertextVerifier } = await deployAndSaveMockCiphertextVerifier(hre);
  const ciphertextVerifierAddress = await ciphertextVerifier.getAddress();
  console.log("Deploying Mock Pk Verifier");
  const { pkVerifier } = await deployAndSaveMockPkVerifier(hre);
  const pkVerifierAddress = await pkVerifier.getAddress();

  console.log("Deploying E3 Program");
  const { e3Program } = await deployAndSaveMockProgram({
    hre,
  });

  const e3ProgramAddress = await e3Program.getAddress();

  console.log("Deploying CKKS E3 Program");
  const { ckksProgramAddress } = await deployAndSaveMockCkksProgram({ hre });

  console.log("Deploying Greco-gated CKKS E3 Program (with Honk verifiers)");
  const { ckksVerifiedProgramAddress } = await deployAndSaveCkksProgram({
    hre,
  });

  console.log(
    "Deploying Greco-gated CKKS E3 Program for ParamSet 3 (statistics)",
  );
  const { ckksVerifiedProgramAddress: ckksVerifiedProgramPs3Address } =
    await deployAndSaveCkksProgram({ hre, paramSet: 3 });

  // Three-leg app programs (Greco + app-validity). Caps mirror the demos:
  // demo/ckks-salary-survey SALARY_CAP=500000, demo/ckks-auction BID_CAP=1000
  // (the auction encrypts RAW bids, cap 1 — the bid cap is the Greco input
  // bound, not the normalization cap).
  console.log("Deploying CKKS salary-survey app program (ParamSet 3)");
  const { programAddress: ckksSalaryProgramAddress } =
    await deployAndSaveCkksAppProgram({ hre, app: "salary", cap: 500_000n });
  console.log("Deploying CKKS auction app program (ParamSet 2)");
  const { programAddress: ckksAuctionProgramAddress } =
    await deployAndSaveCkksAppProgram({ hre, app: "auction", cap: 1n });
  // Credit scoring: features are numerators over FEATURE_CAP=1000 (the
  // fixture's cap; see `gen_ckks_credit_prover`).
  console.log("Deploying CKKS credit-scoring app program (ParamSet 4)");
  const { programAddress: ckksCreditProgramAddress } =
    await deployAndSaveCkksAppProgram({ hre, app: "credit", cap: 1000n });
  // Treasury risk (ParamSet 5): exposures are cap-normalised in the browser.
  console.log("Deploying CKKS treasury-risk app program (ParamSet 5)");
  const { programAddress: ckksTreasuryProgramAddress } =
    await deployAndSaveCkksAppProgram({ hre, app: "treasury", cap: 1n });
  // Federated averaging (ParamSet 5): updates are normalised to [-1, 1] in the browser.
  console.log("Deploying CKKS federated-averaging app program (ParamSet 5)");
  const { programAddress: ckksFedAvgProgramAddress } =
    await deployAndSaveCkksAppProgram({ hre, app: "fedavg", cap: 1n });
  // Private matching (ParamSet 5): two parties per round, vectors normalised to [-1, 1] in the browser.
  console.log("Deploying CKKS private-matching app program (ParamSet 5)");
  const { programAddress: ckksMatchingProgramAddress } =
    await deployAndSaveCkksAppProgram({ hre, app: "matching", cap: 1n });

  console.log(`
        MockDeployments:
        ----------------------------------------------------------------------
        MockComputeProvider:${computeProviderAddress}
        MockDecryptionVerifier:${decryptionVerifierAddress}
        MockCiphertextVerifier:${ciphertextVerifierAddress}
        MockPkVerifier:${pkVerifierAddress}
        MockE3Program:${e3ProgramAddress}
        MockCkksE3Program:${ckksProgramAddress}
        CkksE3Program:${ckksVerifiedProgramAddress}
        CkksE3ProgramPs3:${ckksVerifiedProgramPs3Address}
        CkksSalaryE3Program:${ckksSalaryProgramAddress}
        CkksAuctionE3Program:${ckksAuctionProgramAddress}
        CkksCreditE3Program:${ckksCreditProgramAddress}
        CkksTreasuryE3Program:${ckksTreasuryProgramAddress}
        CkksFedAvgE3Program:${ckksFedAvgProgramAddress}
        CkksMatchingE3Program:${ckksMatchingProgramAddress}
        `);

  return {
    computeProviderAddress,
    decryptionVerifierAddress,
    ciphertextVerifierAddress,
    pkVerifierAddress,
    e3ProgramAddress,
    ckksProgramAddress,
    ckksVerifiedProgramAddress,
    ckksVerifiedProgramPs3Address,
    ckksSalaryProgramAddress,
    ckksAuctionProgramAddress,
    ckksCreditProgramAddress,
    ckksTreasuryProgramAddress,
    ckksFedAvgProgramAddress,
    ckksMatchingProgramAddress,
  };
};
