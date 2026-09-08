// SPDX-License-Identifier: LGPL-3.0-only
import path from "node:path";

import { arg, connect, hasFlag } from "../protocol/cli";
import {
  deploymentPath,
  governanceSafeBuilderPath,
  protocolDir,
  readJson,
  repoRelativePath,
  writeJson,
} from "../protocol/files";
import { currentNodeRelease } from "../protocol/nodeRelease";
import {
  aragonAdminSafeBatch,
  aragonAdminSafeTransactions,
  governanceBatch,
  proposeSafeBatch,
  safeTx,
} from "../protocol/safe";
import type { ProtocolDeployment, SafeTransaction } from "../protocol/types";
import { loadConfig, requireContract } from "../protocol/values";

interface NodeReleasePlan {
  name: string;
  mandatory: boolean;
  nodeReleaseRegistry: string;
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

async function protocolContracts() {
  const { ethers } = await connect();
  const config = loadConfig();
  const deployment = readJson<ProtocolDeployment>(deploymentPath(config));
  const network = await ethers.provider.getNetwork();
  if (Number(network.chainId) !== deployment.chainId) {
    throw new Error("Connected to the wrong network for this deployment file");
  }
  if (!deployment.nodeReleaseRegistry) {
    throw new Error("Deployment has no node release registry");
  }
  await Promise.all([
    requireContract(ethers.provider, deployment.interfold, "Interfold proxy"),
    requireContract(
      ethers.provider,
      deployment.ciphernodeRegistry,
      "ciphernode registry proxy",
    ),
    requireContract(
      ethers.provider,
      deployment.nodeReleaseRegistry,
      "node release registry",
    ),
  ]);
  const interfold = await ethers.getContractAt(
    "Interfold",
    deployment.interfold,
  );
  const registry = await ethers.getContractAt(
    "CiphernodeRegistryOwnable",
    deployment.ciphernodeRegistry,
  );
  const bonding = await ethers.getContractAt(
    "BondingRegistry",
    config.bondingRegistryProxy,
  );
  const releases = await ethers.getContractAt(
    "NodeReleaseRegistry",
    deployment.nodeReleaseRegistry,
  );
  for (const [label, actual, expected] of [
    [
      "Interfold node release registry",
      await interfold.nodeReleaseRegistry(),
      deployment.nodeReleaseRegistry,
    ],
    ["node release owner", await releases.owner(), config.protocolOwner],
    [
      "node release BondingRegistry",
      await releases.bondingRegistry(),
      config.bondingRegistryProxy,
    ],
    [
      "node release CiphernodeRegistry",
      await releases.ciphernodeRegistry(),
      deployment.ciphernodeRegistry,
    ],
  ] as const) {
    if (String(actual).toLowerCase() !== String(expected).toLowerCase()) {
      throw new Error(`${label}: expected ${expected}, got ${actual}`);
    }
  }
  return { ethers, config, deployment, interfold, registry, bonding, releases };
}

async function prepare(): Promise<void> {
  const { config, deployment, interfold, registry, releases } =
    await protocolContracts();
  const mandatory = hasFlag("mandatory");
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
  if (BigInt(release.nodeGeneration) === requiredNodeGeneration) {
    throw new Error(
      "Increase node_generation before preparing a mandatory node-only release",
    );
  }
  if (mandatory) {
    if (!(await interfold.requestsPaused())) {
      throw new Error("Pause E3 requests before a mandatory node cutover");
    }
    const activeE3s = await interfold.activeE3Count();
    const unreleased = await registry.unreleasedCommitteeCount();
    if (activeE3s !== 0n || unreleased !== 0n) {
      throw new Error(
        `Mandatory cutover requires a drained protocol; active E3s ${activeE3s}, unreleased committees ${unreleased}`,
      );
    }
  }

  const txs: SafeTransaction[] = [
    safeTx(
      deployment.nodeReleaseRegistry,
      releases.interface.encodeFunctionData("setRequiredNodeRelease", [
        release.protocolVersion,
        release.nodeGeneration,
      ]),
    ),
  ];
  const rawBatchFile = batchPath(config.name, "upgrade");
  const batch = governanceBatch(config, txs);
  batch.meta.name = `${config.name} ciphernode release ${release.version}`;
  batch.meta.description =
    "Raise the required ciphernode generation after the protocol was paused and drained.";
  writeJson(rawBatchFile, batch);

  let safeBuilderFile: string | undefined;
  if (config.governance) {
    safeBuilderFile = governanceSafeBuilderPath({
      ...config,
      name: `${config.name}.node-release.upgrade`,
    });
    writeJson(safeBuilderFile, aragonAdminSafeBatch(config, txs));
  }
  if (hasFlag("propose-safe")) {
    await proposeSafeBatch(
      config,
      config.governance ? aragonAdminSafeTransactions(config, txs) : txs,
      config.governance?.proposerSafe ?? config.safe,
    );
  }
  const plan: NodeReleasePlan = {
    name: config.name,
    mandatory,
    nodeReleaseRegistry: deployment.nodeReleaseRegistry,
    release,
    safeTransactions: repoRelativePath(rawBatchFile),
    governanceSafeBuilder: safeBuilderFile
      ? repoRelativePath(safeBuilderFile)
      : undefined,
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
    deployment.nodeReleaseRegistry.toLowerCase()
  ) {
    throw new Error("Prepared release plan targets another release registry");
  }
  if (!(await interfold.requestsPaused())) {
    throw new Error("E3 requests are already enabled");
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

  const txs = [
    safeTx(
      deployment.interfold,
      interfold.interface.encodeFunctionData("setRequestsPaused", [false]),
    ),
  ];
  const rawBatchFile = batchPath(config.name, "resume");
  writeJson(rawBatchFile, governanceBatch(config, txs));
  if (config.governance) {
    writeJson(
      governanceSafeBuilderPath({
        ...config,
        name: `${config.name}.node-release.resume`,
      }),
      aragonAdminSafeBatch(config, txs),
    );
  }
  if (hasFlag("propose-safe")) {
    await proposeSafeBatch(
      config,
      config.governance ? aragonAdminSafeTransactions(config, txs) : txs,
      config.governance?.proposerSafe ?? config.safe,
    );
  }
  console.log(`Ciphernode release ${plan.release.version} is ready to resume`);
}

const action = (arg("action") ?? "prepare").toLowerCase();
const run =
  action === "prepare" ? prepare : action === "resume" ? resume : null;
if (!run) throw new Error(`Unknown --action: ${action}`);
run().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
