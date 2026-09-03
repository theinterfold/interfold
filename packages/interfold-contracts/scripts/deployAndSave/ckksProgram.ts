// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import type { HardhatRuntimeEnvironment } from "hardhat/types/hre";

import { getDeploymentChain, storeDeploymentArgs } from "../utils";

interface CkksProgramArgs {
  hre: HardhatRuntimeEnvironment;
  /**
   * Greco circuit param set the verifiers were generated for. The
   * canonical dev set (0) uses the unsuffixed verifier contracts and
   * stores the deployment as `CkksE3Program`; any other set N uses the
   * `...PsNVerifier` contracts and stores `CkksE3ProgramPsN`.
   */
  paramSet?: number;
}

/**
 * Deploys the Greco-gated CKKS E3 program: the two Honk verifiers for the
 * verifiable-encryption legs (`user_data_encryption_ckks_ct0` / `_ct1`,
 * each with its external ZKTranscriptLib/RelationsLib), then the
 * `CkksE3Program` that requires both proofs (bound by the shared
 * u-commitment) before accepting a published input.
 */
export const deployAndSaveCkksProgram = async ({
  hre,
  paramSet = 0,
}: CkksProgramArgs): Promise<{
  ckksVerifiedProgramAddress: string;
}> => {
  const { ethers } = await hre.network.connect();
  const chain = getDeploymentChain(hre);
  const suffix = paramSet === 0 ? "" : `Ps${paramSet}`;

  const deployVerifier = async (
    solFile: string,
    contractName: string,
  ): Promise<string> => {
    const base = `contracts/verifiers/bfv/honk/${solFile}`;
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

  const ct0VerifierAddress = await deployVerifier(
    `UserDataEncryptionCkksCt0${suffix}Verifier.sol`,
    `UserDataEncryptionCkksCt0${suffix}Verifier`,
  );
  const ct1VerifierAddress = await deployVerifier(
    `UserDataEncryptionCkksCt1${suffix}Verifier.sol`,
    `UserDataEncryptionCkksCt1${suffix}Verifier`,
  );

  const programFactory = await ethers.getContractFactory("CkksE3Program");
  const program = await programFactory.deploy(
    ct0VerifierAddress,
    ct1VerifierAddress,
  );
  await program.waitForDeployment();

  const ckksVerifiedProgramAddress = await program.getAddress();
  const blockNumber = await ethers.provider.getBlockNumber();

  storeDeploymentArgs(
    {
      blockNumber,
      address: ckksVerifiedProgramAddress,
    },
    `CkksE3Program${suffix}`,
    chain,
  );

  return { ckksVerifiedProgramAddress };
};
