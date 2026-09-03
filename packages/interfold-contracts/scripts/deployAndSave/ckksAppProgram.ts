// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import type { HardhatRuntimeEnvironment } from "hardhat/types/hre";

import { getDeploymentChain, storeDeploymentArgs } from "../utils";

export type CkksApp = "salary" | "auction";

interface CkksAppProgramArgs {
  hre: HardhatRuntimeEnvironment;
  app: CkksApp;
  /**
   * Public normalization cap the program pins (salary cap for the survey,
   * bid cap for the auction). Must match what participants prove against.
   */
  cap: bigint;
}

/** Per-app wiring: ParamSet, verifier contracts, program contract. */
const APPS: Record<
  CkksApp,
  { paramSet: number; appVerifier: string; program: string; record: string }
> = {
  salary: {
    paramSet: 3,
    appVerifier: "CkksSalaryValidityPs3Verifier",
    program: "CkksSalaryE3Program",
    record: "CkksSalaryE3Program",
  },
  auction: {
    paramSet: 2,
    appVerifier: "CkksAuctionValidityPs2Verifier",
    program: "CkksAuctionE3Program",
    record: "CkksAuctionE3Program",
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

  const program = await (
    await ethers.getContractFactory(wiring.program)
  ).deploy(ct0, ct1, appVerifier, cap);
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
