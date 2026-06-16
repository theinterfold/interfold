// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import type { HardhatRuntimeEnvironment } from "hardhat/types/hre";

import {
  E3RefundManager,
  E3RefundManager__factory as E3RefundManagerFactory,
} from "../../types";
import { getProxyAdmin } from "../proxy";
import { readDeploymentArgs, storeDeploymentArgs } from "../utils";

/**
 * The arguments for the deployAndSaveE3RefundManager function
 */
export interface E3RefundManagerArgs {
  owner?: string;
  interfold?: string;
  treasury?: string;
  hre: HardhatRuntimeEnvironment;
}

/**
 * Deploys the E3RefundManager contract and saves the deployment arguments
 * @param param0 - The deployment arguments
 * @returns The deployed E3RefundManager contract
 */
export const deployAndSaveE3RefundManager = async ({
  owner,
  interfold,
  treasury,
  hre,
}: E3RefundManagerArgs): Promise<{ e3RefundManager: E3RefundManager }> => {
  const { ethers } = await hre.network.connect();
  const [signer] = await ethers.getSigners();
  const chain = hre.globalOptions.network;

  const preDeployedArgs = readDeploymentArgs("E3RefundManager", chain);

  if (
    !owner ||
    !interfold ||
    !treasury ||
    (preDeployedArgs?.constructorArgs?.owner === owner &&
      preDeployedArgs?.constructorArgs?.interfold === interfold &&
      preDeployedArgs?.constructorArgs?.treasury === treasury)
  ) {
    if (!preDeployedArgs?.address) {
      throw new Error(
        "E3RefundManager address not found, it must be deployed first",
      );
    }
    const e3RefundManagerContract = E3RefundManagerFactory.connect(
      preDeployedArgs.address,
      signer,
    );
    return { e3RefundManager: e3RefundManagerContract };
  }

  const e3RefundManagerFactory = await ethers.getContractFactory(
    E3RefundManagerFactory.abi,
    E3RefundManagerFactory.bytecode,
    signer,
  );
  const e3RefundManager = await e3RefundManagerFactory.deploy();
  await e3RefundManager.waitForDeployment();

  const blockNumber = await ethers.provider.getBlockNumber();
  const e3RefundManagerAddress = await e3RefundManager.getAddress();

  const initData = e3RefundManagerFactory.interface.encodeFunctionData(
    "initialize",
    [owner, interfold, treasury],
  );

  const ProxyCF = await ethers.getContractFactory(
    "TransparentUpgradeableProxy",
  );
  const proxy = await ProxyCF.deploy(e3RefundManagerAddress, owner, initData);
  await proxy.waitForDeployment();
  const proxyAddress = await proxy.getAddress();

  const proxyAdminAddress = await getProxyAdmin(ethers.provider, proxyAddress);

  storeDeploymentArgs(
    {
      constructorArgs: {
        owner,
        interfold,
        treasury,
      },
      proxyRecords: {
        initData,
        initialOwner: owner,
        proxyAddress,
        proxyAdminAddress,
        implementationAddress: e3RefundManagerAddress,
      },
      blockNumber,
      address: proxyAddress,
    },
    "E3RefundManager",
    chain,
  );

  const e3RefundManagerContract = E3RefundManagerFactory.connect(
    proxyAddress,
    signer,
  );

  return { e3RefundManager: e3RefundManagerContract };
};
