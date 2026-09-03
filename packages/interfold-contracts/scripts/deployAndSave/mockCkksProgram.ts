// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import type { HardhatRuntimeEnvironment } from "hardhat/types/hre";

import { getDeploymentChain, storeDeploymentArgs } from "../utils";

interface MockCkksProgramArgs {
  hre: HardhatRuntimeEnvironment;
}

/**
 * Deploys the CKKS E3 program (program address => protocol mapping: this
 * program's `validate()` binds `keccak256("fhe.rs:CKKS")`, so requesting
 * through its address selects the CKKS scheme).
 */
export const deployAndSaveMockCkksProgram = async ({
  hre,
}: MockCkksProgramArgs): Promise<{
  ckksProgramAddress: string;
}> => {
  const { ethers } = await hre.network.connect();
  const chain = getDeploymentChain(hre);

  const factory = await ethers.getContractFactory("MockCkksE3Program");
  const program = await factory.deploy();
  await program.waitForDeployment();

  const ckksProgramAddress = await program.getAddress();
  const blockNumber = await ethers.provider.getBlockNumber();

  storeDeploymentArgs(
    {
      blockNumber,
      address: ckksProgramAddress,
    },
    "MockCkksE3Program",
    chain,
  );

  return { ckksProgramAddress };
};
