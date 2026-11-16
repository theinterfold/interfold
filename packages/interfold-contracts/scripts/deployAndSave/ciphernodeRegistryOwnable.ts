// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import type { HardhatRuntimeEnvironment } from "hardhat/types/hre";

import {
  CiphernodeRegistryOwnable,
  CiphernodeRegistryOwnable__factory as CiphernodeRegistryOwnableFactory,
} from "../../types";
import { getProxyAdmin, verifyProxyAdminOwner } from "../proxy";
import {
  getDeploymentChain,
  readDeploymentArgs,
  storeDeploymentArgs,
} from "../utils";

/**
 * The arguments for the deployAndSaveCiphernodeRegistryOwnable function
 */
export interface CiphernodeRegistryOwnableArgs {
  owner?: string;
  submissionWindow?: number;
  poseidonT3Address: string;
  hre: HardhatRuntimeEnvironment;
}

/**
 * Deploys the CiphernodeRegistryOwnable contract and saves the deployment arguments
 * @param param0 - The deployment arguments
 * @returns The deployed CiphernodeRegistryOwnable contract
 */
export const deployAndSaveCiphernodeRegistryOwnable = async ({
  owner,
  submissionWindow,
  poseidonT3Address,
  hre,
}: CiphernodeRegistryOwnableArgs): Promise<{
  ciphernodeRegistry: CiphernodeRegistryOwnable;
}> => {
  const { ethers } = await hre.network.connect();
  const [signer] = await ethers.getSigners();
  const chain = getDeploymentChain(hre);

  const preDeployedArgs = readDeploymentArgs(
    "CiphernodeRegistryOwnable",
    chain,
  );

  if (
    !owner ||
    !submissionWindow ||
    (preDeployedArgs?.constructorArgs?.owner === owner &&
      preDeployedArgs?.constructorArgs?.submissionWindow ===
        submissionWindow.toString())
  ) {
    if (!preDeployedArgs?.address) {
      throw new Error(
        "CiphernodeRegistry address not found, it must be deployed first",
      );
    }
    const ciphernodeRegistryContract = CiphernodeRegistryOwnableFactory.connect(
      preDeployedArgs.address,
      signer,
    );
    return { ciphernodeRegistry: ciphernodeRegistryContract };
  }

  const registrySortitionLibFactory = await ethers.getContractFactory(
    "RegistrySortitionLib",
    signer,
  );
  const registrySortitionLib = await registrySortitionLibFactory.deploy();
  await registrySortitionLib.waitForDeployment();
  const registrySortitionLibAddress = await registrySortitionLib.getAddress();
  const dkgPublicationLib = await ethers.deployContract(
    "DkgPublicationLib",
    signer,
  );
  await dkgPublicationLib.waitForDeployment();
  const dkgPublicationLibAddress = await dkgPublicationLib.getAddress();

  const ciphernodeRegistryFactory = await ethers.getContractFactory(
    CiphernodeRegistryOwnableFactory.abi,
    CiphernodeRegistryOwnableFactory.linkBytecode({
      "npm/poseidon-solidity@0.0.5/PoseidonT3.sol:PoseidonT3":
        poseidonT3Address,
      "project/contracts/lib/RegistrySortitionLib.sol:RegistrySortitionLib":
        registrySortitionLibAddress,
      "project/contracts/lib/DkgPublicationLib.sol:DkgPublicationLib":
        dkgPublicationLibAddress,
    }),
    signer,
  );

  const ciphernodeRegistry = await ciphernodeRegistryFactory.deploy();
  await ciphernodeRegistry.waitForDeployment();
  const blockNumber = await ethers.provider.getBlockNumber();
  const ciphernodeRegistryAddress = await ciphernodeRegistry.getAddress();

  const initData = ciphernodeRegistryFactory.interface.encodeFunctionData(
    "initialize",
    [owner, submissionWindow],
  );

  const ProxyCF = await ethers.getContractFactory(
    "TransparentUpgradeableProxy",
  );
  const proxy = await ProxyCF.deploy(
    ciphernodeRegistryAddress,
    owner,
    initData,
  );
  await proxy.waitForDeployment();
  const proxyAddress = await proxy.getAddress();

  const proxyAdminAddress = await getProxyAdmin(ethers.provider, proxyAddress);

  storeDeploymentArgs(
    {
      constructorArgs: {
        owner,
        submissionWindow: submissionWindow.toString(),
      },
      proxyRecords: {
        initData,
        initialOwner: owner,
        proxyAddress,
        proxyAdminAddress,
        implementationAddress: ciphernodeRegistryAddress,
      },
      libraries: {
        PoseidonT3: poseidonT3Address,
        RegistrySortitionLib: registrySortitionLibAddress,
        DkgPublicationLib: dkgPublicationLibAddress,
      },
      blockNumber,
      address: proxyAddress,
    },
    "CiphernodeRegistryOwnable",
    chain,
  );
  storeDeploymentArgs(
    { address: registrySortitionLibAddress, blockNumber },
    "RegistrySortitionLib",
    chain,
  );
  storeDeploymentArgs(
    { address: dkgPublicationLibAddress, blockNumber },
    "DkgPublicationLib",
    chain,
  );

  const ciphernodeRegistryContract = CiphernodeRegistryOwnableFactory.connect(
    proxyAddress,
    signer,
  );

  return { ciphernodeRegistry: ciphernodeRegistryContract };
};

export const upgradeAndSaveCiphernodeRegistryOwnable = async ({
  poseidonT3Address,
  ownerAddress,
  hre,
}: {
  poseidonT3Address: string;
  ownerAddress: string;
  hre: HardhatRuntimeEnvironment;
}): Promise<{
  ciphernodeRegistry: CiphernodeRegistryOwnable;
  implementationAddress: string;
}> => {
  const { ethers } = await hre.network.connect();
  const [signer] = await ethers.getSigners();
  const chain = hre.globalOptions.network;

  const preDeployedArgs = readDeploymentArgs(
    "CiphernodeRegistryOwnable",
    chain,
  );
  if (!preDeployedArgs?.address) {
    throw new Error(
      "CiphernodeRegistryOwnable proxy not found. Deploy first before upgrading.",
    );
  }

  const proxyAddress = preDeployedArgs.address;

  const autoProxyAdminAddress = await getProxyAdmin(
    ethers.provider,
    proxyAddress,
  );
  console.log("Auto-deployed ProxyAdmin address:", autoProxyAdminAddress);

  const registrySortitionLibFactory = await ethers.getContractFactory(
    "RegistrySortitionLib",
    signer,
  );
  const registrySortitionLib = await registrySortitionLibFactory.deploy();
  await registrySortitionLib.waitForDeployment();
  const registrySortitionLibAddress = await registrySortitionLib.getAddress();
  const dkgPublicationLib = await ethers.deployContract(
    "DkgPublicationLib",
    signer,
  );
  await dkgPublicationLib.waitForDeployment();
  const dkgPublicationLibAddress = await dkgPublicationLib.getAddress();

  const ciphernodeRegistryFactory = await ethers.getContractFactory(
    CiphernodeRegistryOwnableFactory.abi,
    CiphernodeRegistryOwnableFactory.linkBytecode({
      "npm/poseidon-solidity@0.0.5/PoseidonT3.sol:PoseidonT3":
        poseidonT3Address,
      "project/contracts/lib/RegistrySortitionLib.sol:RegistrySortitionLib":
        registrySortitionLibAddress,
      "project/contracts/lib/DkgPublicationLib.sol:DkgPublicationLib":
        dkgPublicationLibAddress,
    }),
    signer,
  );

  const newImplementation = await ciphernodeRegistryFactory.deploy();
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
      libraries: {
        ...preDeployedArgs.libraries,
        PoseidonT3: poseidonT3Address,
        RegistrySortitionLib: registrySortitionLibAddress,
        DkgPublicationLib: dkgPublicationLibAddress,
      },
    },
    "CiphernodeRegistryOwnable",
    chain,
  );
  const blockNumber = await ethers.provider.getBlockNumber();
  storeDeploymentArgs(
    { address: registrySortitionLibAddress, blockNumber },
    "RegistrySortitionLib",
    chain,
  );
  storeDeploymentArgs(
    { address: dkgPublicationLibAddress, blockNumber },
    "DkgPublicationLib",
    chain,
  );

  const ciphernodeRegistryContract = CiphernodeRegistryOwnableFactory.connect(
    proxyAddress,
    signer,
  );
  return {
    ciphernodeRegistry: ciphernodeRegistryContract,
    implementationAddress: newImplementationAddress,
  };
};
