// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { type Provider, getAddress } from "ethers";

/**
 * ERC-1967 admin slot: keccak256("eip1967.proxy.admin") - 1
 * This is where TransparentUpgradeableProxy stores the ProxyAdmin address
 * https://docs.openzeppelin.com/contracts/5.x/api/proxy#ERC1967Utils-getAdmin--
 */
export const ERC1967_ADMIN_SLOT =
  "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103";

/**
 * Gets the ProxyAdmin address from a TransparentUpgradeableProxy
 * @param provider The ethers provider
 * @param proxyAddress The address of the proxy contract
 * @returns The address of the auto-deployed ProxyAdmin
 */
export async function getProxyAdmin(
  provider: Provider,
  proxyAddress: string,
): Promise<string> {
  const adminSlotValue = await provider.getStorage(
    proxyAddress,
    ERC1967_ADMIN_SLOT,
  );

  // Extract the address from the storage slot (last 20 bytes)
  const addressHex = "0x" + adminSlotValue.slice(-40);

  return getAddress(addressHex);
}

/**
 * Verifies that the ProxyAdmin is owned by the expected owner
 * @param proxyAdmin The ProxyAdmin contract instance
 * @param expectedOwner The expected owner address
 * @throws Error if owner doesn't match
 */
export async function verifyProxyAdminOwner(
  proxyAdmin: any,
  expectedOwner: string,
): Promise<void> {
  const actualOwner = await proxyAdmin.owner();
  if (actualOwner.toLowerCase() !== expectedOwner.toLowerCase()) {
    throw new Error(
      `ProxyAdmin owner mismatch. Expected ${expectedOwner}, got ${actualOwner}`,
    );
  }
}
