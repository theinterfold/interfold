// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import type { HardhatRuntimeEnvironment } from "hardhat/types/hre";

import {
  InterfoldToken,
  InterfoldToken__factory as InterfoldTokenFactory,
} from "../../types";
import {
  getDeploymentChain,
  readDeploymentArgs,
  storeDeploymentArgs,
} from "../utils";

/**
 * The arguments for the deployAndSaveInterfoldToken function
 */
export interface InterfoldTokenArgs {
  owner?: string;
  ccaStart?: bigint;
  ccaEnd?: bigint;
  claimSource?: string;
  bondingRegistry?: string;
  noMoreLocks?: bigint;
  hre: HardhatRuntimeEnvironment;
}

/**
 * Disables transfer restrictions for local development
 */
async function disableTransferRestrictionsForLocal(
  contract: InterfoldToken,
  chain: string,
): Promise<void> {
  if (chain !== "localhost" && chain !== "hardhat") {
    return;
  }
  console.log("Disabling transfer restrictions for chain", chain);
  console.log("Contract address", await contract.getAddress());

  const tgeTs = await contract.tgeTimestamp();
  if (tgeTs === 0n) {
    console.warn(
      "TGE not yet fired — call tge() after advancing time past CCA_END + 45 days.",
    );
  } else {
    console.log("Token is already Live (TGE timestamp:", tgeTs.toString(), ")");
  }
}

/**
 * Deploys the InterfoldToken contract and saves the deployment arguments
 * @param param0 - The deployment arguments
 * @returns The deployed InterfoldToken contract
 */
export const deployAndSaveInterfoldToken = async ({
  owner,
  ccaStart,
  ccaEnd,
  claimSource,
  bondingRegistry,
  noMoreLocks,
  hre,
}: InterfoldTokenArgs): Promise<{
  interfoldToken: InterfoldToken;
}> => {
  const { ethers } = await hre.network.connect();
  const [signer] = await ethers.getSigners();
  const chain = getDeploymentChain(hre);

  const preDeployedArgs = readDeploymentArgs("InterfoldToken", chain);

  if (
    !owner ||
    ccaStart === undefined ||
    ccaEnd === undefined ||
    !claimSource ||
    !bondingRegistry ||
    noMoreLocks === undefined ||
    preDeployedArgs?.constructorArgs?.owner === owner
  ) {
    if (!preDeployedArgs?.address) {
      throw new Error(
        "InterfoldToken address not found, it must be deployed first",
      );
    }
    const interfoldTokenContract = InterfoldTokenFactory.connect(
      preDeployedArgs.address,
      signer,
    );

    await disableTransferRestrictionsForLocal(interfoldTokenContract, chain);

    return { interfoldToken: interfoldTokenContract };
  }

  const interfoldTokenFactory =
    await ethers.getContractFactory("InterfoldToken");
  const interfoldToken = await interfoldTokenFactory.deploy(
    owner,
    ccaStart,
    ccaEnd,
    noMoreLocks,
    claimSource,
    bondingRegistry,
  );

  await interfoldToken.waitForDeployment();

  const blockNumber = await ethers.provider.getBlockNumber();

  const interfoldTokenAddress = await interfoldToken.getAddress();

  storeDeploymentArgs(
    {
      constructorArgs: {
        owner,
        ccaStart: ccaStart.toString(),
        ccaEnd: ccaEnd.toString(),
        claimSource,
        bondingRegistry,
        noMoreLocks: noMoreLocks.toString(),
      },
      blockNumber,
      address: interfoldTokenAddress,
    },
    "InterfoldToken",
    chain,
  );

  const interfoldTokenContract = InterfoldTokenFactory.connect(
    interfoldTokenAddress,
    signer,
  );

  await disableTransferRestrictionsForLocal(interfoldTokenContract, chain);

  return { interfoldToken: interfoldTokenContract };
};
