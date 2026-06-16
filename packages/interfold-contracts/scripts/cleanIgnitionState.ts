// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { cleanLocalDeployments } from "./utils";

/**
 * Cleans deployment records for a specific network from deployed_contracts.json
 *
 * @param networkName - The network name (e.g., "localhost", "hardhat")
 */
export const cleanDeploymentRecords = (networkName: string): void => {
  cleanLocalDeployments(networkName);
  console.log(`Cleaned deployment records for local network '${networkName}'`);
};

/**
 * Automatically clean Ignition state and deployment records for localhost/hardhat networks before deployment.
 * This prevents stale state issues when Anvil is restarted.
 */
export const autoCleanForLocalhost = async (
  networkName: string,
): Promise<void> => {
  const localNetworks = ["localhost", "hardhat", "anvil", "ganache"];
  if (localNetworks.includes(networkName)) {
    console.log(
      `Detected local network '${networkName}', auto-cleaning stale deployment state...`,
    );
    cleanDeploymentRecords(networkName);
  }
};
