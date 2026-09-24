// SPDX-License-Identifier: LGPL-3.0-only
import path from "node:path";
import { pathToFileURL } from "node:url";

import { assertRefreshedOwnerCapacity } from "../../tasks/committeeCapacity";
import {
  type Interfold,
  Interfold__factory as InterfoldFactory,
  type NodeReleaseRegistry,
  NodeReleaseRegistry__factory as NodeReleaseRegistryFactory,
} from "../../types";
import { arg, connect, hasFlag } from "../protocol/cli";
import {
  deploymentPath,
  governanceSafeBuilderPath,
  protocolDir,
  readJson,
  repoRelativePath,
  writeJson,
} from "../protocol/files";
import {
  type CurrentNodeRelease,
  currentNodeRelease,
  deployNodeReleaseRegistry,
  requiresNodeReleasePolicyUpdate,
} from "../protocol/nodeRelease";
import {
  aragonAdminSafeBatch,
  aragonAdminSafeTransactions,
  governanceBatch,
  proposeSafeBatch,
  safeTx,
} from "../protocol/safe";
import type {
  ProtocolConfigFile,
  ProtocolDeployment,
  SafeTransaction,
} from "../protocol/types";
import { loadConfig, requireContract } from "../protocol/values";

interface NodeReleasePlan {
  name: string;
  mandatory: boolean;
  nodeReleaseRegistry: string;
  previousNodeReleaseRegistry?: string;
  preservesTerminalState: boolean;
  release: ReturnType<typeof currentNodeRelease>;
  safeTransactions: string;
  governanceSafeBuilder?: string;
}

function planPath(name: string): string {
  return path.join(protocolDir, `${name}.node-release.upgrade.json`);
}

function batchPath(name: string, action: "upgrade" | "resume"): string {
  return path.join(protocolDir, `${name}.node-release.${action}.safe.json`);
}

function assertAddress(label: string, actual: string, expected: string): void {
  if (actual.toLowerCase() !== expected.toLowerCase()) {
    throw new Error(`${label}: expected ${expected}, got ${actual}`);
  }
}

async function assertControllerBindings(
  controller: NodeReleaseRegistry,
  interfold: Interfold,
): Promise<void> {
  for (const field of [
    "owner",
    "bondingRegistry",
    "ciphernodeRegistry",
  ] as const) {
    const [actual, expected] = await Promise.all([
      controller[field](),
      interfold[field](),
    ]);
    assertAddress(`Release controller ${field}`, actual, expected);
  }
}

async function protocolContracts() {
  const { ethers } = await connect();
  const config = loadConfig();
  const deployment = readJson<ProtocolDeployment>(deploymentPath(config));
  const network = await ethers.provider.getNetwork();
  if (Number(network.chainId) !== deployment.chainId) {
    throw new Error("Connected to the wrong network for this deployment file");
  }
  await Promise.all([
    requireContract(ethers.provider, deployment.interfold, "Interfold proxy"),
    requireContract(
      ethers.provider,
      deployment.ciphernodeRegistry,
      "ciphernode registry proxy",
    ),
  ]);
  const interfold = InterfoldFactory.connect(
    deployment.interfold,
    ethers.provider,
  );
  const controllerAddress = await interfold.nodeReleaseRegistry();
  await requireContract(
    ethers.provider,
    controllerAddress,
    "node release registry",
  );
  const registry = await ethers.getContractAt(
    "CiphernodeRegistryOwnable",
    deployment.ciphernodeRegistry,
  );
  const bonding = await ethers.getContractAt(
    "BondingRegistry",
    config.bondingRegistryProxy,
  );
  const releases = NodeReleaseRegistryFactory.connect(
    controllerAddress,
    ethers.provider,
  );
  for (const [label, actual, expected] of [
    ["Interfold owner", await interfold.owner(), config.protocolOwner],
    [
      "Interfold BondingRegistry",
      await interfold.bondingRegistry(),
      config.bondingRegistryProxy,
    ],
    [
      "Interfold CiphernodeRegistry",
      await interfold.ciphernodeRegistry(),
      deployment.ciphernodeRegistry,
    ],
  ] as const) {
    assertAddress(label, actual, expected);
  }
  await assertControllerBindings(releases, interfold);
  return { ethers, config, deployment, interfold, registry, bonding, releases };
}

async function assertPausedAndIdle(interfold: Interfold): Promise<void> {
  if (!(await interfold.requestsPaused())) {
    throw new Error("Pause E3 requests before a mandatory node cutover");
  }
  const activeE3s = await interfold.activeE3Count();
  if (activeE3s !== 0n) {
    throw new Error(
      `Wait for active E3s to finish before a mandatory node cutover; active E3s ${activeE3s}`,
    );
  }
}

async function deployController(): Promise<void> {
  const { ethers, config, deployment, interfold, releases } =
    await protocolContracts();
  await assertPausedAndIdle(interfold);
  const replacement = await deployNodeReleaseRegistry(
    ethers,
    config.protocolOwner,
    config.bondingRegistryProxy,
    deployment.ciphernodeRegistry,
  );
  writeJson(
    path.join(protocolDir, `${config.name}.node-release.controller.json`),
    {
      chainId: deployment.chainId,
      previousNodeReleaseRegistry: await releases.getAddress(),
      nodeReleaseRegistry: replacement.address,
    },
  );
  console.log(`Controller deployed, not activated: ${replacement.address}`);
  console.log(
    `Prepare its governance batch with --action prepare --mandatory --replacement ${replacement.address}`,
  );
}

/** Builds ordered governance calls without sending a transaction. */
export async function nodeReleaseUpgradeTransactions(
  interfold: Interfold,
  release: CurrentNodeRelease,
  replacement?: NodeReleaseRegistry,
): Promise<SafeTransaction[]> {
  const provider = interfold.runner?.provider;
  if (!provider)
    throw new Error("A provider is required to check the release policy");
  const currentAddress = await interfold.nodeReleaseRegistry();
  const current = NodeReleaseRegistryFactory.connect(currentAddress, provider);
  const [protocol, generation, owner] = await Promise.all([
    current.requiredProtocolVersion(),
    current.requiredNodeGeneration(),
    interfold.owner(),
  ]);
  if (BigInt(release.protocolVersion) !== protocol) {
    throw new Error("A node-only upgrade cannot change protocolVersion");
  }
  const needsUpdate = requiresNodeReleasePolicyUpdate(
    release,
    protocol,
    generation,
  );
  const target = replacement?.connect(provider) ?? current;
  const targetAddress = await target.getAddress();
  const transactions: SafeTransaction[] = [];

  if (replacement) {
    if (targetAddress.toLowerCase() === currentAddress.toLowerCase()) {
      throw new Error("The replacement is already the active controller");
    }
    await requireContract(
      provider,
      targetAddress,
      "replacement release controller",
    );
    await assertControllerBindings(target, interfold);
    await target.inheritReleasePolicy.staticCall(currentAddress, {
      from: owner,
    });
    transactions.push(
      safeTx(
        targetAddress,
        target.interface.encodeFunctionData("inheritReleasePolicy", [
          currentAddress,
        ]),
      ),
      safeTx(
        await interfold.getAddress(),
        interfold.interface.encodeFunctionData("setNodeReleaseRegistry", [
          targetAddress,
        ]),
      ),
    );
  } else if (needsUpdate) {
    // Legacy controllers still enforce their full-drain guard.
    await current.setRequiredNodeRelease.staticCall(
      release.protocolVersion,
      release.nodeGeneration,
      { from: owner },
    );
  }
  if (needsUpdate) {
    transactions.push(
      safeTx(
        targetAddress,
        target.interface.encodeFunctionData("setRequiredNodeRelease", [
          release.protocolVersion,
          release.nodeGeneration,
        ]),
      ),
    );
  }
  return transactions;
}

async function writeReleaseBatch(
  config: ProtocolConfigFile,
  action: "upgrade" | "resume",
  transactions: SafeTransaction[],
  description: string,
) {
  const rawBatchFile = batchPath(config.name, action);
  const batch = governanceBatch(config, transactions);
  batch.meta.name = `${config.name} ciphernode release ${action}`;
  batch.meta.description = description;
  writeJson(rawBatchFile, batch);

  let safeBuilderFile: string | undefined;
  if (config.governance) {
    safeBuilderFile = governanceSafeBuilderPath({
      ...config,
      name: `${config.name}.node-release.${action}`,
    });
    const safeBatch = aragonAdminSafeBatch(config, transactions);
    safeBatch.meta.name = batch.meta.name;
    safeBatch.meta.description = description;
    writeJson(safeBuilderFile, safeBatch);
  }
  if (hasFlag("propose-safe")) {
    await proposeSafeBatch(
      config,
      config.governance
        ? aragonAdminSafeTransactions(config, transactions)
        : transactions,
      config.governance?.proposerSafe ?? config.safe,
    );
  }
  return {
    safeTransactions: repoRelativePath(rawBatchFile),
    governanceSafeBuilder: safeBuilderFile
      ? repoRelativePath(safeBuilderFile)
      : undefined,
  };
}

async function prepare(): Promise<void> {
  const { ethers, config, interfold, registry, releases } =
    await protocolContracts();
  const mandatory = hasFlag("mandatory");
  const replacementAddress = arg("replacement");
  if (replacementAddress && !mandatory) {
    throw new Error("A controller replacement requires --mandatory");
  }
  const release = currentNodeRelease();
  const [requiredProtocolVersion, requiredNodeGeneration] = await Promise.all([
    releases.requiredProtocolVersion(),
    releases.requiredNodeGeneration(),
  ]);
  if (BigInt(release.protocolVersion) !== requiredProtocolVersion) {
    throw new Error(
      "This node-only release tool cannot change protocolVersion; include that change in the contract upgrade proposal",
    );
  }
  if (BigInt(release.nodeGeneration) < requiredNodeGeneration) {
    throw new Error("nodeGeneration cannot move backwards");
  }
  if (!mandatory) {
    if (BigInt(release.nodeGeneration) !== requiredNodeGeneration) {
      throw new Error(
        "A node generation change is mandatory; run this command with --mandatory",
      );
    }
    console.log(
      `Ciphernode ${release.version} is compatible with protocol ${release.protocolVersion}, generation ${release.nodeGeneration}; no governance transaction is required`,
    );
    return;
  }
  if (
    BigInt(release.nodeGeneration) === requiredNodeGeneration &&
    !replacementAddress
  ) {
    throw new Error(
      "Increase node_generation before preparing a mandatory node-only release",
    );
  }
  await assertPausedAndIdle(interfold);
  const unreleased = await registry.unreleasedCommitteeCount();
  const preservesTerminalState = hasFlag("preserves-terminal-state");
  if (unreleased !== 0n && !preservesTerminalState) {
    throw new Error(
      `${unreleased} terminal committees remain. Verify that the release preserves their evidence and settlement duties, then pass --preserves-terminal-state. Do not reset their data.`,
    );
  }

  const replacement = replacementAddress
    ? NodeReleaseRegistryFactory.connect(replacementAddress, ethers.provider)
    : undefined;
  const transactions = await nodeReleaseUpgradeTransactions(
    interfold,
    release,
    replacement,
  );
  const files = await writeReleaseBatch(
    config,
    "upgrade",
    transactions,
    "Update node eligibility after active E3s finish. Preserve terminal committee obligations and keep requests paused.",
  );
  const plan: NodeReleasePlan = {
    name: config.name,
    mandatory,
    nodeReleaseRegistry: await (replacement ?? releases).getAddress(),
    previousNodeReleaseRegistry: replacementAddress
      ? await releases.getAddress()
      : undefined,
    preservesTerminalState,
    release,
    ...files,
  };
  writeJson(planPath(config.name), plan);
  console.log(
    `Mandatory ciphernode release prepared: ${release.version} (${release.releaseId})`,
  );
}

async function resume(): Promise<void> {
  const { config, deployment, interfold, bonding, releases } =
    await protocolContracts();
  const plan = readJson<NodeReleasePlan>(planPath(config.name));
  if (!plan.mandatory) {
    throw new Error("Only a mandatory release has a resume step");
  }
  if (
    plan.nodeReleaseRegistry.toLowerCase() !==
    (await releases.getAddress()).toLowerCase()
  ) {
    throw new Error("Prepared release plan targets another release registry");
  }
  await assertPausedAndIdle(interfold);
  if (!hasFlag("ciphernodes-restarted")) {
    throw new Error(
      "Confirm that enough eligible ciphernodes restarted, are online, and can reach each other, then pass --ciphernodes-restarted",
    );
  }
  if (
    (await releases.requiredProtocolVersion()) !==
      BigInt(plan.release.protocolVersion) ||
    (await releases.requiredNodeGeneration()) !==
      BigInt(plan.release.nodeGeneration)
  ) {
    throw new Error("Live required release does not match the prepared plan");
  }
  const minimumActive = config.interfold.committeeThresholds.reduce(
    (maximum, threshold) => {
      const total = BigInt(threshold.total);
      return total > maximum ? total : maximum;
    },
    0n,
  );
  const active = await bonding.numActiveOperators();
  if (active < minimumActive) {
    throw new Error(
      `Only ${active} release-ready operators are active; ${minimumActive} are required`,
    );
  }

  await assertRefreshedOwnerCapacity(bonding, minimumActive);

  const txs = [
    safeTx(
      deployment.interfold,
      interfold.interface.encodeFunctionData("setRequestsPaused", [false]),
    ),
  ];
  await writeReleaseBatch(
    config,
    "resume",
    txs,
    "Resume requests after the node release update and complete operator eligibility refresh.",
  );
  console.log(`Ciphernode release ${plan.release.version} is ready to resume`);
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
  const actions: Record<string, () => Promise<void>> = {
    prepare,
    resume,
    "deploy-controller": deployController,
  };
  const action = (arg("action") ?? "prepare").toLowerCase();
  const run = actions[action];
  if (!run) throw new Error(`Unknown --action: ${action}`);
  run().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}
