// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import type { HardhatRuntimeEnvironment } from "hardhat/types/hre";

import {
  SlashingManager,
  SlashingManager__factory as SlashingManagerFactory,
} from "../../types";
import {
  getDeploymentChain,
  readDeploymentArgs,
  storeDeploymentArgs,
} from "../utils";

/**
 * The arguments for the deployAndSaveSlashingManager function
 */
export interface SlashingManagerArgs {
  admin?: string;
  /**
   * Initial delay (seconds) for the two-step DEFAULT_ADMIN handover enforced by
   * `AccessControlDefaultAdminRules`. Defaults to 2 days when omitted (M-17).
   */
  initialDelay?: number | bigint;
  hre: HardhatRuntimeEnvironment;
}

const DEFAULT_ADMIN_DELAY = 60n * 60n * 24n * 2n; // 2 days

/**
 * Deploys the SlashingManager contract and saves the deployment arguments
 * @param param0 - The deployment arguments
 * @returns The deployed SlashingManager contract
 */
export const deployAndSaveSlashingManager = async ({
  admin,
  initialDelay,
  hre,
}: SlashingManagerArgs): Promise<{
  slashingManager: SlashingManager;
}> => {
  const { ethers } = await hre.network.connect();
  const [signer] = await ethers.getSigners();
  const chain = getDeploymentChain(hre);

  const delay =
    initialDelay !== undefined ? BigInt(initialDelay) : DEFAULT_ADMIN_DELAY;

  // Reject zero delay: a zero `initialDelay` collapses the two-step
  // DEFAULT_ADMIN_ROLE handover (M-17) into a single transaction.
  if (delay === 0n) {
    throw new Error(
      "SlashingManager initialDelay must be > 0 (two-step admin handover)",
    );
  }

  const preDeployedArgs = readDeploymentArgs("SlashingManager", chain);

  if (
    !admin ||
    (preDeployedArgs?.constructorArgs?.admin === admin &&
      String(preDeployedArgs?.constructorArgs?.initialDelay ?? "") ===
        String(delay))
  ) {
    if (!preDeployedArgs?.address) {
      throw new Error(
        "SlashingManager address not found, it must be deployed first",
      );
    }
    const slashingManagerContract = SlashingManagerFactory.connect(
      preDeployedArgs.address,
      signer,
    );
    return { slashingManager: slashingManagerContract };
  }

  const slashingManagerFactory =
    await ethers.getContractFactory("SlashingManager");
  const slashingManager = await slashingManagerFactory.deploy(delay, admin);

  await slashingManager.waitForDeployment();

  const blockNumber = await ethers.provider.getBlockNumber();

  const slashingManagerAddress = await slashingManager.getAddress();

  storeDeploymentArgs(
    {
      constructorArgs: {
        initialDelay: delay.toString(),
        admin,
      },
      blockNumber,
      address: slashingManagerAddress,
    },
    "SlashingManager",
    chain,
  );

  const slashingManagerContract = SlashingManagerFactory.connect(
    slashingManagerAddress,
    signer,
  );

  return { slashingManager: slashingManagerContract };
};
