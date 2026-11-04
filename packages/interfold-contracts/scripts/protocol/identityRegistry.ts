// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { deployProxy } from "./proxies";
import { deployedAddress } from "./values";

/**
 * Deploys OwnerIdentityRegistry behind a transparent proxy. `owner` owns the registry and the
 * proxy admin; `verifier` is the first verifier (the zero address leaves registration closed).
 */
export async function deployOwnerIdentityRegistry(
  ethers: any,
  owner: string,
  verifier: string,
) {
  const factory = await ethers.getContractFactory("OwnerIdentityRegistry");
  const implementation = await factory.deploy();
  await implementation.waitForDeployment();
  const implementationAddress = await deployedAddress(implementation);
  const { proxy, proxyAdmin } = await deployProxy(
    ethers,
    implementationAddress,
    owner,
    factory.interface.encodeFunctionData("initialize", [owner, verifier]),
  );
  return {
    registry: factory.attach(proxy),
    proxy,
    proxyAdmin,
    implementation: implementationAddress,
  };
}
