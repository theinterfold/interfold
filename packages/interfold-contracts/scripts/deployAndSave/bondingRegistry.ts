// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import type { HardhatRuntimeEnvironment } from "hardhat/types/hre";

import {
  BondingRegistry,
  BondingRegistry__factory as BondingRegistryFactory,
} from "../../types";
import { getProxyAdmin, verifyProxyAdminOwner } from "../proxy";
import {
  getDeploymentChain,
  readDeploymentArgs,
  storeDeploymentArgs,
} from "../utils";

/**
 * The arguments for the deployAndSaveBondingRegistry function
 */
export interface BondingRegistryArgs {
  owner?: string;
  ticketToken?: string;
  licenseToken?: string;
  registry?: string;
  slashedFundsTreasury?: string;
  ticketPrice?: string;
  licenseRequiredBond?: string;
  minTicketBalance?: number;
  exitDelay?: number;
  hre: HardhatRuntimeEnvironment;
}

/**
 * Deploys the BondingRegistry contract and saves the deployment arguments
 * @param param0 - The deployment arguments
 * @returns The deployed BondingRegistry contract
 */
export const deployAndSaveBondingRegistry = async ({
  owner,
  ticketToken,
  licenseToken,
  registry,
  slashedFundsTreasury,
  ticketPrice,
  licenseRequiredBond,
  minTicketBalance,
  exitDelay,
  hre,
}: BondingRegistryArgs): Promise<{
  bondingRegistry: BondingRegistry;
}> => {
  const { ethers } = await hre.network.connect();
  const [signer] = await ethers.getSigners();
  const chain = getDeploymentChain(hre);

  const preDeployedArgs = readDeploymentArgs("BondingRegistry", chain);

  if (
    !owner ||
    !ticketToken ||
    !licenseToken ||
    !registry ||
    !slashedFundsTreasury ||
    !ticketPrice ||
    !licenseRequiredBond ||
    minTicketBalance === undefined ||
    exitDelay === undefined ||
    (preDeployedArgs?.constructorArgs?.owner === owner &&
      preDeployedArgs?.constructorArgs?.ticketToken === ticketToken &&
      preDeployedArgs?.constructorArgs?.licenseToken === licenseToken &&
      preDeployedArgs?.constructorArgs?.registry === registry &&
      preDeployedArgs?.constructorArgs?.slashedFundsTreasury ===
        slashedFundsTreasury &&
      preDeployedArgs?.constructorArgs?.ticketPrice === ticketPrice &&
      preDeployedArgs?.constructorArgs?.licenseRequiredBond ===
        licenseRequiredBond &&
      preDeployedArgs?.constructorArgs?.minTicketBalance ===
        minTicketBalance.toString() &&
      preDeployedArgs?.constructorArgs?.exitDelay === exitDelay.toString())
  ) {
    if (!preDeployedArgs?.address) {
      throw new Error(
        "BondingRegistry address not found, it must be deployed first",
      );
    }
    const bondingRegistryContract = BondingRegistryFactory.connect(
      preDeployedArgs.address,
      signer,
    );
    return { bondingRegistry: bondingRegistryContract };
  }

  const blockNumber = await ethers.provider.getBlockNumber();

  const bondingRegistryFactory =
    await ethers.getContractFactory("BondingRegistry");

  const bondingRegistry = await bondingRegistryFactory.deploy();
  await bondingRegistry.waitForDeployment();
  const bondingRegistryAddress = await bondingRegistry.getAddress();

  const initData = bondingRegistryFactory.interface.encodeFunctionData(
    "initialize",
    [
      owner,
      ticketToken,
      licenseToken,
      registry,
      slashedFundsTreasury,
      ticketPrice,
      licenseRequiredBond,
      minTicketBalance,
      exitDelay,
    ],
  );

  const ProxyCF = await ethers.getContractFactory(
    "TransparentUpgradeableProxy",
  );
  const proxy = await ProxyCF.deploy(bondingRegistryAddress, owner, initData);
  await proxy.waitForDeployment();
  const proxyAddress = await proxy.getAddress();

  const proxyAdminAddress = await getProxyAdmin(ethers.provider, proxyAddress);

  storeDeploymentArgs(
    {
      constructorArgs: {
        owner,
        ticketToken,
        licenseToken,
        registry,
        slashedFundsTreasury,
        ticketPrice,
        licenseRequiredBond,
        minTicketBalance: minTicketBalance.toString(),
        exitDelay: exitDelay.toString(),
      },
      proxyRecords: {
        initData,
        initialOwner: owner,
        proxyAddress,
        proxyAdminAddress,
        implementationAddress: bondingRegistryAddress,
      },
      blockNumber,
      address: proxyAddress,
    },
    "BondingRegistry",
    chain,
  );

  const bondingRegistryContract = BondingRegistryFactory.connect(
    proxyAddress,
    signer,
  );

  return { bondingRegistry: bondingRegistryContract };
};

/**
 * Upgrades the BondingRegistry implementation while keeping the same proxy address
 * @param param0 - The upgrade arguments
 * @returns The upgraded BondingRegistry contract (same proxy address)
 */
export const upgradeAndSaveBondingRegistry = async ({
  ownerAddress,
  hre,
}: {
  ownerAddress: string;
  hre: HardhatRuntimeEnvironment;
}): Promise<{
  bondingRegistry: BondingRegistry;
  implementationAddress: string;
}> => {
  const { ethers } = await hre.network.connect();
  const [signer] = await ethers.getSigners();
  const chain = hre.globalOptions.network;

  const preDeployedArgs = readDeploymentArgs("BondingRegistry", chain);
  if (!preDeployedArgs?.address) {
    throw new Error(
      "BondingRegistry proxy not found. Deploy first before upgrading.",
    );
  }

  const proxyAddress = preDeployedArgs.address;

  const autoProxyAdminAddress = await getProxyAdmin(
    ethers.provider,
    proxyAddress,
  );
  console.log("Auto-deployed ProxyAdmin address:", autoProxyAdminAddress);

  const bondingRegistryFactory = await ethers.getContractFactory(
    "BondingRegistry",
    signer,
  );

  const newImplementation = await bondingRegistryFactory.deploy();
  await newImplementation.waitForDeployment();
  const newImplementationAddress = await newImplementation.getAddress();
  console.log("New Implementation Address:", newImplementationAddress);

  const proxyAdmin = await ethers.getContractAt(
    "ProxyAdmin",
    autoProxyAdminAddress,
    signer,
  );
  await verifyProxyAdminOwner(proxyAdmin, ownerAddress);

  // TODO: Add init data if needed
  const initData = "0x";
  const upgradeTx = await proxyAdmin.upgradeAndCall(
    proxyAddress,
    newImplementationAddress,
    initData,
  );
  await upgradeTx.wait();

  const existingProxyRecords = preDeployedArgs.proxyRecords
    ? Object.fromEntries(
        Object.entries(preDeployedArgs.proxyRecords).filter(
          ([, value]) => value !== undefined,
        ),
      )
    : {};

  const proxyRecords: Record<string, string | string[]> = {
    ...existingProxyRecords,
    implementationAddress: newImplementationAddress,
  };

  if (initData !== "0x") {
    proxyRecords.initData = initData;
  }

  storeDeploymentArgs(
    {
      ...preDeployedArgs,
      proxyRecords,
    },
    "BondingRegistry",
    chain,
  );

  const bondingRegistryContract = BondingRegistryFactory.connect(
    proxyAddress,
    signer,
  );

  return {
    bondingRegistry: bondingRegistryContract,
    implementationAddress: newImplementationAddress,
  };
};
