// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import type { HardhatRuntimeEnvironment } from "hardhat/types/hre";

import {
  MockComputeProvider,
  MockComputeProvider__factory as MockComputeProviderFactory,
} from "../../types";
import { storeDeploymentArgs } from "../utils";

export const deployAndSaveMockComputeProvider = async (
  hre: HardhatRuntimeEnvironment,
): Promise<{
  computeProvider: MockComputeProvider;
}> => {
  const { ethers } = await hre.network.connect();

  const computeProviderFactory = await ethers.getContractFactory(
    "MockComputeProvider",
  );
  const computeProvider = await computeProviderFactory.deploy();

  await computeProvider.waitForDeployment();

  const computeProviderAddress = await computeProvider.getAddress();

  const [signer] = await ethers.getSigners();
  const chain = hre.globalOptions.network;
  const blockNumber = await ethers.provider.getBlockNumber();

  storeDeploymentArgs(
    {
      blockNumber,
      address: computeProviderAddress,
    },
    "MockComputeProvider",
    chain,
  );

  const computeProviderContract = MockComputeProviderFactory.connect(
    computeProviderAddress,
    signer,
  );

  return { computeProvider: computeProviderContract };
};
