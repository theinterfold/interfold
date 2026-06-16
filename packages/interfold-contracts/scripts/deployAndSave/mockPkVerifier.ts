// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import type { HardhatRuntimeEnvironment } from "hardhat/types/hre";

import {
  MockPkVerifier,
  MockPkVerifier__factory as MockPkVerifierFactory,
} from "../../types";
import { getDeploymentChain, storeDeploymentArgs } from "../utils";

export const deployAndSaveMockPkVerifier = async (
  hre: HardhatRuntimeEnvironment,
): Promise<{
  pkVerifier: MockPkVerifier;
}> => {
  const { ethers } = await hre.network.connect();
  const [signer] = await ethers.getSigners();
  const chain = getDeploymentChain(hre);

  const pkVerifierFactory = await ethers.getContractFactory("MockPkVerifier");
  const pkVerifier = await pkVerifierFactory.deploy();

  await pkVerifier.waitForDeployment();
  const pkVerifierAddress = await pkVerifier.getAddress();

  const blockNumber = await ethers.provider.getBlockNumber();

  storeDeploymentArgs(
    {
      blockNumber,
      address: pkVerifierAddress,
    },
    "MockPkVerifier",
    chain,
  );

  const pkVerifierContract = MockPkVerifierFactory.connect(
    pkVerifierAddress,
    signer,
  );

  return { pkVerifier: pkVerifierContract };
};
