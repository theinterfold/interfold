// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import type { HardhatRuntimeEnvironment } from "hardhat/types/hre";

import { getDeploymentChain, storeDeploymentArgs } from "../utils";

export type CkksApp =
  | "salary"
  | "auction"
  | "credit"
  | "treasury"
  | "fedavg"
  | "matching";

interface CkksAppProgramArgs {
  hre: HardhatRuntimeEnvironment;
  app: CkksApp;
  /**
   * Public normalization cap the program pins (salary cap for the survey,
   * bid cap for the auction, feature cap for credit scoring). Must match
   * what participants prove against.
   */
  cap: bigint;
}

/** Per-app wiring: ParamSet, verifier contracts, program contract. */
const APPS: Record<
  CkksApp,
  {
    paramSet: number;
    appVerifier: string;
    program: string;
    record: string;
    /**
     * Whether the program pins the normalization cap in its CONSTRUCTOR.
     * The salary and auction programs do. Credit scoring registers the cap
     * per round (`registerRound`, alongside the issuer root, the model and
     * the applicant list), so its constructor takes the verifiers only —
     * passing a 4th argument makes ethers read it as the overrides object
     * ("invalid overrides parameter", INVALID_ARGUMENT).
     */
    capInConstructor: boolean;
  }
> = {
  salary: {
    paramSet: 3,
    appVerifier: "CkksSalaryValidityPs3Verifier",
    program: "CkksSalaryE3Program",
    record: "CkksSalaryE3Program",
    capInConstructor: true,
  },
  auction: {
    paramSet: 2,
    appVerifier: "CkksAuctionValidityPs2Verifier",
    program: "CkksAuctionE3Program",
    record: "CkksAuctionE3Program",
    capInConstructor: true,
  },
  credit: {
    paramSet: 4,
    appVerifier: "CkksCreditValidityPs4Verifier",
    program: "CkksCreditE3Program",
    record: "CkksCreditE3Program",
    capInConstructor: false,
  },
  // Treasury risk registers its public weights + DAO list per round
  // (`registerRound`); inputs are cap-normalised in the browser (cap 1).
  treasury: {
    paramSet: 5,
    appVerifier: "CkksTreasuryValidityPs5Verifier",
    program: "CkksTreasuryE3Program",
    record: "CkksTreasuryE3Program",
    capInConstructor: false,
  },
  // Federated averaging registers its norm bound + minimum client count +
  // client list per round (`registerRound`); updates are already in [-1, 1]
  // (cap 1). The verifier name is what `generate-verifiers.ts` derives from
  // the circuit package `ckks_fedavg_validity_ps5`.
  fedavg: {
    paramSet: 5,
    appVerifier: "CkksFedavgValidityPs5Verifier",
    program: "CkksFedAvgE3Program",
    record: "CkksFedAvgE3Program",
    capInConstructor: false,
  },
  // Private matching (ParamSet 5): exactly two parties per round, registered
  // via `registerRound(roundId, [a, b])`; slot 0 = A (forward layout), slot 1 =
  // B (reversed layout). Vectors are cap-normalised to [-1, 1] in the browser
  // (cap 1), so the constructor takes the three verifiers only
  // (`capInConstructor: false`, like credit / treasury / fedavg). The verifier
  // name is what `generate-verifiers.ts` derives from `ckks_matching_validity_ps5`.
  matching: {
    paramSet: 5,
    appVerifier: "CkksMatchingValidityPs5Verifier",
    program: "CkksMatchingE3Program",
    record: "CkksMatchingE3Program",
    capInConstructor: false,
  },
};

/**
 * Deploys a three-leg CKKS app program: the two Greco Honk verifiers for
 * its ParamSet (`user_data_encryption_ckks_ct{0,1}_psN`, each with its
 * external ZKTranscriptLib/RelationsLib), the app-validity verifier
 * (`ckks_<app>_validity_psN`), then the program contract that requires
 * all three proofs (bound by the shared u/m commitments) before accepting
 * a published input.
 */
export const deployAndSaveCkksAppProgram = async ({
  hre,
  app,
  cap,
}: CkksAppProgramArgs): Promise<{
  programAddress: string;
  /** The connection the deployment ran on (hardhat-3 connections are isolated). */
  ethers: Awaited<
    ReturnType<HardhatRuntimeEnvironment["network"]["connect"]>
  >["ethers"];
}> => {
  const { ethers } = await hre.network.connect();
  const chain = getDeploymentChain(hre);
  const wiring = APPS[app];
  const suffix = `Ps${wiring.paramSet}`;

  const deployVerifier = async (contractName: string): Promise<string> => {
    const base = `contracts/verifiers/bfv/honk/${contractName}.sol`;
    const zkLib = await (
      await ethers.getContractFactory(`${base}:ZKTranscriptLib`)
    ).deploy();
    await zkLib.waitForDeployment();
    const relLib = await (
      await ethers.getContractFactory(`${base}:RelationsLib`)
    ).deploy();
    await relLib.waitForDeployment();
    const factory = await ethers.getContractFactory(`${base}:${contractName}`, {
      libraries: {
        [`project/${base}:ZKTranscriptLib`]: await zkLib.getAddress(),
        [`project/${base}:RelationsLib`]: await relLib.getAddress(),
      },
    });
    const verifier = await factory.deploy();
    await verifier.waitForDeployment();
    return verifier.getAddress();
  };

  const ct0 = await deployVerifier(
    `UserDataEncryptionCkksCt0${suffix}Verifier`,
  );
  const ct1 = await deployVerifier(
    `UserDataEncryptionCkksCt1${suffix}Verifier`,
  );
  const appVerifier = await deployVerifier(wiring.appVerifier);

  const factory = await ethers.getContractFactory(wiring.program);
  const program = wiring.capInConstructor
    ? await factory.deploy(ct0, ct1, appVerifier, cap)
    : await factory.deploy(ct0, ct1, appVerifier);
  await program.waitForDeployment();

  const programAddress = await program.getAddress();
  const blockNumber = await ethers.provider.getBlockNumber();
  storeDeploymentArgs(
    { blockNumber, address: programAddress },
    wiring.record,
    chain,
  );

  return { programAddress, ethers };
};
