// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import type { HardhatRuntimeEnvironment } from "hardhat/types/hre";

import { MockUSDC, MockUSDC__factory as MockUSDCFactory } from "../../types";
import {
  getDeploymentChain,
  readDeploymentArgs,
  storeDeploymentArgs,
} from "../utils";

/**
 * The arguments for the deployAndSaveMockStableToken function
 */
export interface MockStableTokenArgs {
  initialSupply?: number;
  hre: HardhatRuntimeEnvironment;
}

/**
 * Deploys the MockStableToken contract and saves the deployment arguments
 * @param param0 - The deployment arguments
 * @returns The deployed MockStableToken contract
 */
export const deployAndSaveMockStableToken = async ({
  initialSupply,
  hre,
}: MockStableTokenArgs): Promise<{
  mockStableToken: MockUSDC;
}> => {
  const { ethers } = await hre.network.connect();
  const [signer] = await ethers.getSigners();
  const chain = getDeploymentChain(hre);

  const preDeployedArgs = readDeploymentArgs("MockUSDC", chain);

  if (
    initialSupply === undefined ||
    preDeployedArgs?.constructorArgs?.initialSupply ===
      initialSupply?.toString()
  ) {
    if (!preDeployedArgs?.address) {
      throw new Error("MockUSDC address not found, it must be deployed first");
    }
    const mockStableTokenContract = MockUSDCFactory.connect(
      preDeployedArgs.address,
      signer,
    );
    return { mockStableToken: mockStableTokenContract };
  }

  const mockStableTokenFactory = await ethers.getContractFactory("MockUSDC");
  const mockStableToken = await mockStableTokenFactory.deploy(initialSupply);

  await mockStableToken.waitForDeployment();

  const blockNumber = await ethers.provider.getBlockNumber();

  const mockStableTokenAddress = await mockStableToken.getAddress();

  storeDeploymentArgs(
    {
      constructorArgs: {
        initialSupply: initialSupply?.toString(),
      },
      blockNumber,
      address: mockStableTokenAddress,
    },
    "MockUSDC",
    chain,
  );

  const mockStableTokenContract = MockUSDCFactory.connect(
    mockStableTokenAddress,
    signer,
  );

  return { mockStableToken: mockStableTokenContract };
};
