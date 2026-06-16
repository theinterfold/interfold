// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import type { HardhatRuntimeEnvironment } from "hardhat/types/hre";

import {
  InterfoldTicketToken,
  InterfoldTicketToken__factory as InterfoldTicketTokenFactory,
} from "../../types";
import {
  getDeploymentChain,
  readDeploymentArgs,
  storeDeploymentArgs,
} from "../utils";

/**
 * The arguments for the deployAndSaveInterfoldTicketToken function
 */
export interface InterfoldTicketTokenArgs {
  baseToken?: string;
  registry?: string;
  owner?: string;
  hre: HardhatRuntimeEnvironment;
}

/**
 * Deploys the InterfoldTicketToken contract and saves the deployment arguments
 * @param param0 - The deployment arguments
 * @returns The deployed InterfoldTicketToken contract
 */
export const deployAndSaveInterfoldTicketToken = async ({
  baseToken,
  registry,
  owner,
  hre,
}: InterfoldTicketTokenArgs): Promise<{
  interfoldTicketToken: InterfoldTicketToken;
}> => {
  const { ethers } = await hre.network.connect();
  const [signer] = await ethers.getSigners();
  const chain = getDeploymentChain(hre);

  const preDeployedArgs = readDeploymentArgs("InterfoldTicketToken", chain);

  if (
    !baseToken ||
    !registry ||
    !owner ||
    (preDeployedArgs?.constructorArgs?.baseToken === baseToken &&
      preDeployedArgs?.constructorArgs?.registry === registry &&
      preDeployedArgs?.constructorArgs?.owner === owner)
  ) {
    if (!preDeployedArgs?.address) {
      throw new Error(
        "InterfoldTicketToken address not found, it must be deployed first",
      );
    }
    const interfoldTicketTokenContract = InterfoldTicketTokenFactory.connect(
      preDeployedArgs.address,
      signer,
    );
    return { interfoldTicketToken: interfoldTicketTokenContract };
  }

  const interfoldTicketTokenFactory = await ethers.getContractFactory(
    "InterfoldTicketToken",
  );
  const interfoldTicketToken = await interfoldTicketTokenFactory.deploy(
    baseToken,
    registry,
    owner,
  );

  await interfoldTicketToken.waitForDeployment();

  const blockNumber = await ethers.provider.getBlockNumber();

  const interfoldTicketTokenAddress = await interfoldTicketToken.getAddress();

  storeDeploymentArgs(
    {
      constructorArgs: {
        baseToken,
        registry,
        owner,
      },
      blockNumber,
      address: interfoldTicketTokenAddress,
    },
    "InterfoldTicketToken",
    chain,
  );

  const interfoldTicketTokenContract = InterfoldTicketTokenFactory.connect(
    interfoldTicketTokenAddress,
    signer,
  );

  return { interfoldTicketToken: interfoldTicketTokenContract };
};
