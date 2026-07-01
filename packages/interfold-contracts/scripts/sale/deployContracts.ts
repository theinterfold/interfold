// SPDX-License-Identifier: LGPL-3.0-only
import { getProxyAdmin } from "../proxy";
import { ZERO } from "./constants";
import type { HardhatEthers } from "./types";
import { deployedAddress } from "./values";

export async function deployMockBondingRegistryProxy(
  ethers: HardhatEthers,
  safe: string,
) {
  const implFactory = await ethers.getContractFactory("MockBondingRegistry");
  const impl = await implFactory.deploy();
  await impl.waitForDeployment();
  const implementation = await deployedAddress(impl);

  const proxyFactory = await ethers.getContractFactory(
    "TransparentUpgradeableProxy",
  );
  const proxy = await proxyFactory.deploy(implementation, safe, "0x");
  await proxy.waitForDeployment();
  const proxyAddress = await deployedAddress(proxy);
  const proxyAdmin = await getProxyAdmin(ethers.provider, proxyAddress);

  return { implementation, proxy: proxyAddress, proxyAdmin };
}

export async function deploySaleDeployer(
  ethers: HardhatEthers,
  safe: string,
): Promise<string> {
  const factory = await ethers.getContractFactory("InterfoldTokenSaleDeployer");
  const deployer = await factory.deploy(safe);
  await deployer.waitForDeployment();
  return deployedAddress(deployer);
}

export async function deployPredicateValidationHook(
  ethers: HardhatEthers,
  opts: {
    owner: string;
    registry: string;
    policyID: string;
    requireSenderIsOwner: boolean;
  },
): Promise<string> {
  const factory = await ethers.getContractFactory("PredicateValidationHook");
  const hook = await factory.deploy(
    opts.owner,
    opts.registry,
    opts.policyID,
    opts.requireSenderIsOwner,
  );
  await hook.waitForDeployment();
  return deployedAddress(hook);
}

export async function deployMockCcaFactory(
  ethers: HardhatEthers,
): Promise<string> {
  const factory = await ethers.getContractFactory("MockCCAFactory");
  const mock = await factory.deploy(ZERO);
  await mock.waitForDeployment();
  return deployedAddress(mock);
}

