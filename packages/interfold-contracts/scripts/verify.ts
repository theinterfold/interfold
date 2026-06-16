// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { execSync } from "child_process";
import fs from "fs";
import path from "path";

import { readAllDeployments } from "./utils";

/**
 * Find the fully qualified contract name by searching the contracts directory
 * @param contractName - Simple contract name (e.g., "Interfold")
 * @param contractsDir - Directory to search (default: "contracts")
 * @returns Fully qualified name or undefined if not found
 */
const findContractPath = (
  contractName: string,
  artifactsDir: string = "artifacts",
): string | undefined => {
  const searchDir = (dir: string): string | undefined => {
    const files = fs.readdirSync(dir);

    for (const file of files) {
      const fullPath = path.join(dir, file);
      const stat = fs.statSync(fullPath);

      if (stat.isDirectory()) {
        const result = searchDir(fullPath);
        if (result) return result;
      } else if (file === `${contractName}.json`) {
        try {
          const artifact = JSON.parse(fs.readFileSync(fullPath, "utf-8"));

          if (artifact.sourceName && artifact.contractName === contractName) {
            const sourceName = artifact.sourceName;

            // Normalize the source name by removing leading './' if present
            let normalizedPath = sourceName;
            if (normalizedPath.startsWith("./")) {
              normalizedPath = normalizedPath.slice(2);
            }

            // Handle external packages (from node_modules or @ packages)
            if (
              sourceName.startsWith("./@") ||
              sourceName.startsWith("@") ||
              sourceName.includes("node_modules")
            ) {
              console.log(
                `📦 Found external contract: ${contractName} (from ${normalizedPath})`,
              );
            }

            return `${normalizedPath}:${contractName}`;
          }
        } catch (error) {
          console.warn(`Failed to parse artifact at ${fullPath}:`, error);
        }
      }
    }
    return undefined;
  };

  return searchDir(artifactsDir);
};

/**
 * Verify a single contract using Hardhat CLI
 * @param address - Contract address
 * @param constructorArgs - Constructor arguments as a record
 * @param network - Network name
 */
const verifyContract = (
  contractName: string,
  address: string,
  constructorArgs: Record<string, string | string[]> | undefined,
  network: string,
): void => {
  // Create a temporary args file
  const argsFile = path.join(process.cwd(), `verify-args-${address}.cjs`);

  try {
    if (constructorArgs) {
      const argsArray = Object.values(constructorArgs);

      const fileContent = `module.exports = ${JSON.stringify(argsArray, null, 2)};`;
      fs.writeFileSync(argsFile, fileContent);

      const command = `pnpm hardhat verify --build-profile default --network ${network} --contract ${contractName} ${address} --constructor-args-path ${argsFile}`;

      console.log(`Executing: ${command}`);
      execSync(command, { stdio: "inherit" });
      console.log(`✅ Contract verified successfully at ${address}\n`);
    } else {
      const command = `pnpm hardhat verify --build-profile default --network ${network} --contract ${contractName} ${address}`;
      execSync(command, { stdio: "inherit" });
    }
  } catch (error: unknown) {
    if ((error as Error).message?.includes("Already Verified")) {
      console.log(`ℹ️  Contract at ${address} is already verified\n`);
    } else {
      console.error(
        `❌ Failed to verify contract at ${address}:`,
        (error as Error).message,
        "\n",
      );
    }
  } finally {
    // ensure that we always clean up even if there was some early failure
    if (fs.existsSync(argsFile)) {
      fs.unlinkSync(argsFile);
    }
  }
};

/**
 * Deploy and verify all contracts on a given chain
 * @param chain - The chain to verify the contracts on
 */
export const verifyContracts = (chain: string): void => {
  const deployments = readAllDeployments();
  const chainDeployments = deployments[chain];

  if (!chainDeployments) {
    console.log(`❌ No deployments found for chain: ${chain}`);
    return;
  }

  const contractNames = Object.keys(chainDeployments);

  console.log(
    `\n🔍 Verifying ${contractNames.length} contracts on ${chain}...\n`,
  );

  contractNames.forEach((contractName, _) => {
    // we skip PoseidonT3 as it's a library
    if (contractName === "PoseidonT3") {
      console.log(
        `ℹ️  Skipping verification for library contract: ${contractName}`,
      );
      return;
    }

    const deployment = chainDeployments[contractName];
    const isProxy = Boolean(deployment.proxyRecords?.implementationAddress);

    if (isProxy && deployment.proxyRecords) {
      console.log(`  📦 Proxy deployment detected`);

      console.log(`  ├─ Verifying TransparentUpgradeableProxy...`);
      verifyContract(
        "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol:TransparentUpgradeableProxy",
        deployment.address,
        {
          _logic: deployment.proxyRecords.implementationAddress,
          _owner: deployment.proxyRecords.initialOwner,
          _data: deployment.proxyRecords.initData,
        },
        chain,
      );

      console.log(`  ├─ Verifying ProxyAdmin...`);
      verifyContract(
        "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol:ProxyAdmin",
        deployment.proxyRecords.proxyAdminAddress as string,
        { owner: deployment.proxyRecords.initialOwner },
        chain,
      );
    }

    // Verify the main contract (or implementation if proxy)
    const fullyQualifiedName = findContractPath(contractName);

    if (!fullyQualifiedName) {
      console.log(
        `  ❌ Could not find contract source for ${contractName}. Skipping.\n`,
      );
      return;
    }

    const targetAddress = isProxy
      ? (deployment.proxyRecords?.implementationAddress as string)
      : deployment.address;

    const constructorArgs = isProxy ? undefined : deployment.constructorArgs;

    console.log(
      `  ${isProxy ? "└─" : "  "} Verifying ${isProxy ? "implementation" : "contract"} at ${targetAddress.slice(0, 10)}...`,
    );

    verifyContract(fullyQualifiedName, targetAddress, constructorArgs, chain);

    console.log(`  ✅ ${contractName} verification complete\n`);
  });

  console.log(`\n🎉 Verification process completed for ${chain}!\n`);
};
