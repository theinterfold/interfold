// SPDX-License-Identifier: LGPL-3.0-only
import { getProxyAdmin } from "../proxy";
import { deployedAddress } from "./values";

export async function deployProxy(
  ethers: any,
  implementation: string,
  owner: string,
  initData: string,
) {
  const proxyFactory = await ethers.getContractFactory(
    "TransparentUpgradeableProxy",
  );
  const proxy = await proxyFactory.deploy(implementation, owner, initData);
  await proxy.waitForDeployment();
  const proxyAddress = await deployedAddress(proxy);
  const proxyAdmin = await getProxyAdmin(ethers.provider, proxyAddress);
  return { proxy: proxyAddress, proxyAdmin };
}
