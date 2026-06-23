// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import type { HardhatRuntimeEnvironment } from "hardhat/types/hre";

import { Faucet, Faucet__factory as FaucetFactory } from "../../types";
import {
  getDeploymentChain,
  readDeploymentArgs,
  storeDeploymentArgs,
} from "../utils";

/**
 * The arguments for the deployAndSaveFaucet function
 */
export interface FaucetArgs {
  fold: string;
  feeToken: string;
  hre: HardhatRuntimeEnvironment;
}

/**
 * Deploys the Faucet contract and saves the deployment arguments
 * @param param0 - The deployment arguments
 * @returns The deployed Faucet contract
 */
export const deployAndSaveFaucet = async ({
  fold,
  feeToken,
  hre,
}: FaucetArgs): Promise<{
  faucet: Faucet;
}> => {
  const { ethers } = await hre.network.connect();
  const [signer] = await ethers.getSigners();
  const chain = getDeploymentChain(hre);

  const preDeployedArgs = readDeploymentArgs("Faucet", chain);

  if (
    preDeployedArgs?.constructorArgs?.fold === fold &&
    preDeployedArgs?.constructorArgs?.feeToken === feeToken
  ) {
    if (!preDeployedArgs?.address) {
      throw new Error("Faucet address not found, it must be deployed first");
    }
    const faucetContract = FaucetFactory.connect(
      preDeployedArgs.address,
      signer,
    );
    return { faucet: faucetContract };
  }

  const faucetFactory = await ethers.getContractFactory("Faucet");
  const faucet = await faucetFactory.deploy(fold, feeToken);

  await faucet.waitForDeployment();

  const blockNumber = await ethers.provider.getBlockNumber();

  const faucetAddress = await faucet.getAddress();

  storeDeploymentArgs(
    {
      constructorArgs: {
        fold,
        feeToken,
      },
      blockNumber,
      address: faucetAddress,
    },
    "Faucet",
    chain,
  );

  const faucetContract = FaucetFactory.connect(faucetAddress, signer);

  return { faucet: faucetContract };
};
