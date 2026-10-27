// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { verifyContract } from "@nomicfoundation/hardhat-verify/verify";
import hre from "hardhat";
import {
  createHardhatRuntimeEnvironment,
  importUserConfig,
  resolveHardhatConfigPath,
} from "hardhat/hre";
import type { ArtifactManager } from "hardhat/types/artifacts";

/** Hardhat and Ganache chain IDs. No public verifier serves them. */
const LOCAL_CHAIN_IDS = new Set([31337n, 1337n]);

/** Blocks to wait after the last deployment, so that Etherscan has indexed every contract. */
const CONFIRMATIONS = 5;

export interface RecordedDeployment {
  network: string;
  /** False for an in-process Hardhat network, which no verifier can read. */
  live: boolean;
  address: string;
  /** Artifact name or fully qualified name; absent when the factory was built from an ABI. */
  contract?: string;
  abi?: unknown;
  constructorArgs: unknown[];
  libraries?: Record<string, string>;
  transaction: {
    hash: string;
    chainId: bigint;
    wait(confirms?: number): Promise<unknown>;
  };
}

interface Connection {
  ethers: any;
  networkName: string;
  networkConfig: { type: string };
}

const recorded: RecordedDeployment[] = [];

/** The deployments that the next `verifyRecordedDeployments` call will submit. */
export function recordedDeployments(): readonly RecordedDeployment[] {
  return recorded;
}

/**
 * Record each contract that `connection.ethers` deploys, with its exact constructor arguments and
 * libraries, so that `verifyRecordedDeployments` can publish its source at the end of the run.
 */
export function recordDeployments<T extends Connection>(connection: T): T {
  const { ethers } = connection;
  const save = (contract: any, fields: Partial<RecordedDeployment>) => {
    const transaction = contract.deploymentTransaction();
    if (!transaction) return;
    recorded.push({
      network: connection.networkName,
      live: connection.networkConfig.type === "http",
      address: String(contract.target),
      constructorArgs: [],
      transaction,
      ...fields,
    });
  };

  const getContractFactory = ethers.getContractFactory;
  ethers.getContractFactory = async (nameOrAbi: unknown, ...rest: any[]) => {
    const factory = await getContractFactory(nameOrAbi, ...rest);
    const deploy = factory.deploy.bind(factory);
    factory.deploy = async (...args: unknown[]) => {
      const contract = await deploy(...args);
      save(contract, {
        // A trailing overrides object is not a constructor argument.
        constructorArgs: args.slice(0, factory.interface.deploy.inputs.length),
        ...(typeof nameOrAbi === "string"
          ? { contract: nameOrAbi, libraries: rest[0]?.libraries }
          : { abi: nameOrAbi }),
      });
      return contract;
    };
    return factory;
  };

  // `deployContract` builds its factory without `ethers.getContractFactory`.
  const deployContract = ethers.deployContract;
  ethers.deployContract = async (
    name: string,
    argsOrOptions?: any,
    options?: any,
  ) => {
    const contract = await deployContract(name, argsOrOptions, options);
    const hasArgs = Array.isArray(argsOrOptions);
    save(contract, {
      contract: name,
      constructorArgs: hasArgs ? argsOrOptions : [],
      libraries: (hasArgs ? options : argsOrOptions)?.libraries,
    });
    return contract;
  };

  return connection;
}

/**
 * hardhat-verify needs `<source>:<contract>`, but the deploy scripts mostly pass bare names. For a
 * factory built from an ABI, find the artifact with that ABI: the plugin's own bytecode search reads
 * the full build info once for every artifact.
 */
export async function fullyQualifiedName(
  artifacts: ArtifactManager,
  deployment: Pick<RecordedDeployment, "contract" | "abi">,
): Promise<string | undefined> {
  if (deployment.contract !== undefined) {
    const artifact = await artifacts.readArtifact(deployment.contract);
    return `${artifact.sourceName}:${artifact.contractName}`;
  }
  const abi = JSON.stringify(deployment.abi);
  const matches = [];
  for (const name of await artifacts.getAllFullyQualifiedNames()) {
    if (JSON.stringify((await artifacts.readArtifact(name)).abi) === abi) {
      matches.push(name);
    }
  }
  return matches.length === 1 ? matches[0] : undefined;
}

/**
 * Publish the source of every contract recorded on a public network: on Sourcify always, and on
 * Etherscan when `ETHERSCAN_API_KEY` is set. `SKIP_SOURCE_VERIFICATION=1` (or `true`) turns it
 * off.
 *
 * The run has already deployed and written its records, so a failure is reported but leaves the
 * exit code alone: a failed exit would invite a re-run that deploys again.
 */
export async function verifyRecordedDeployments(): Promise<void> {
  const deployments = recorded
    .splice(0)
    .filter((d) => d.live && !LOCAL_CHAIN_IDS.has(d.transaction.chainId));
  if (deployments.length === 0) return;
  if (["1", "true"].includes(process.env.SKIP_SOURCE_VERIFICATION ?? "")) {
    console.log(
      `\nSource verification skipped for ${deployments.length} contracts (SKIP_SOURCE_VERIFICATION).`,
    );
    return;
  }

  const failures: string[] = [];
  for (const network of new Set(deployments.map((d) => d.network))) {
    try {
      await verifyOnNetwork(
        network,
        deployments.filter((d) => d.network === network),
        failures,
      );
    } catch (error) {
      failures.push(`${network}: ${reason(error)}`);
    }
  }

  if (failures.length === 0) {
    console.log("\nSource verification complete.");
    return;
  }
  console.warn(`
Source verification failed ${failures.length} time(s). The deployment itself is complete.
${failures.map((failure) => `  - ${failure}`).join("\n")}
Retry a contract with:
  pnpm hardhat verify <sourcify|etherscan> --network <network> --build-profile default --contract <source>:<name> <address> [constructor args]
`);
}

async function verifyOnNetwork(
  network: string,
  deployments: RecordedDeployment[],
  failures: string[],
): Promise<void> {
  // A runtime of its own: the plugin connects to the runtime's network, and without a build
  // profile it compiles with `production`, whose settings are not those of the deployed bytecode.
  const configPath =
    hre.config.paths.config ?? (await resolveHardhatConfigPath());
  const verifyHre = await createHardhatRuntimeEnvironment(
    await importUserConfig(configPath),
    { config: configPath, network, buildProfile: "default" },
    hre.config.paths.root,
  );
  const providers = verifyHre.config.verify.etherscan.enabled
    ? (["sourcify", "etherscan"] as const)
    : (["sourcify"] as const);

  console.log(
    `\nVerifying ${deployments.length} contracts on ${providers.join(" and ")} (${network}); each waits for ${CONFIRMATIONS} confirmations first.`,
  );
  if (providers.length === 1) {
    console.log("Set ETHERSCAN_API_KEY to also verify on Etherscan.");
  }

  for (const deployment of deployments) {
    // Per deployment: a reverted one (the run's last, when it stopped the run) must not keep the
    // ones before it from being submitted.
    try {
      await deployment.transaction.wait(CONFIRMATIONS);
    } catch (error) {
      failures.push(
        `${network} ${deployment.address} ${deployment.contract ?? "(ABI factory)"}: ${reason(error)}`,
      );
      continue;
    }
    for (const provider of providers) {
      let contract: string | undefined;
      try {
        contract = await fullyQualifiedName(verifyHre.artifacts, deployment);
        await verifyContract(
          {
            address: deployment.address,
            contract,
            constructorArgs: deployment.constructorArgs,
            libraries: deployment.libraries,
            provider,
            creationTxHash:
              provider === "sourcify" ? deployment.transaction.hash : undefined,
          },
          verifyHre,
        );
      } catch (error) {
        failures.push(
          `${provider} ${network} ${deployment.address} ${contract ?? deployment.contract ?? "(contract not found)"}: ${reason(error)}`,
        );
      }
    }
  }
}

/** An ethers error carries the whole receipt in `message`; `shortMessage` is the readable part. */
function reason(error: unknown): string {
  const { shortMessage, message } = (error ?? {}) as {
    shortMessage?: string;
    message?: string;
  };
  return shortMessage ?? message ?? String(error);
}
