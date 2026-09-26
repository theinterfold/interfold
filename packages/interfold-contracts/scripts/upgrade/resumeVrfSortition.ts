// SPDX-License-Identifier: LGPL-3.0-only
import path from "node:path";

import { assertRefreshedOwnerCapacity } from "../../tasks/committeeCapacity";
import { connect, hasFlag } from "../protocol/cli";
import {
  deploymentPath,
  governanceSafeBuilderPath,
  protocolDir,
  readJson,
  writeJson,
} from "../protocol/files";
import {
  assertValidatedVrfDeploymentMatchesPlan,
  assertVrfSubscription,
  assertVrfUpgradePlanMatchesDeployment,
  requireCiphernodeRestartAcknowledgement,
  requirePlannedRandomnessConfig,
} from "../protocol/randomness";
import {
  aragonAdminSafeBatch,
  aragonAdminSafeTransactions,
  governanceBatch,
  proposeSafeBatch,
  safeTx,
} from "../protocol/safe";
import type {
  ProtocolDeployment,
  SafeTransaction,
  VrfSortitionUpgradePlan,
} from "../protocol/types";
import { loadConfig, requireContract } from "../protocol/values";
import { proxyImplementation } from "./safeProxyUpgrade";

function upgradePlanPath(name: string): string {
  return path.join(protocolDir, `${name}.vrf-sortition.upgrade.json`);
}

function resumeBatchPath(name: string): string {
  return path.join(protocolDir, `${name}.vrf-sortition.resume.safe.json`);
}

export async function prepareVrfSortitionResume(): Promise<void> {
  requireCiphernodeRestartAcknowledgement(hasFlag("ciphernodes-restarted"));

  const { ethers } = await connect();
  const config = loadConfig();
  const deployment = readJson<ProtocolDeployment>(deploymentPath(config));
  const plan = readJson<VrfSortitionUpgradePlan>(upgradePlanPath(config.name));
  const network = await ethers.provider.getNetwork();
  assertVrfUpgradePlanMatchesDeployment(
    config,
    deployment,
    plan,
    network.chainId,
  );
  const randomness = requirePlannedRandomnessConfig(config, plan);
  const effectiveConfig = { ...config, randomness };
  assertValidatedVrfDeploymentMatchesPlan(deployment, plan);

  await Promise.all([
    requireContract(ethers.provider, deployment.interfold, "Interfold proxy"),
    requireContract(
      ethers.provider,
      deployment.ciphernodeRegistry,
      "ciphernode registry proxy",
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
  const liveRegistryImplementation = await proxyImplementation(
    ethers,
    deployment.ciphernodeRegistry,
  );
  if (
    liveRegistryImplementation.toLowerCase() !==
    plan.registryImplementation.toLowerCase()
  ) {
    throw new Error(
      `registry implementation: expected ${plan.registryImplementation}, got ${liveRegistryImplementation}`,
    );
  }
  const liveInterfoldImplementation = await proxyImplementation(
    ethers,
    deployment.interfold,
  );
  if (
    liveInterfoldImplementation.toLowerCase() !==
    plan.interfoldImplementation.toLowerCase()
  ) {
    throw new Error(
      `Interfold implementation: expected ${plan.interfoldImplementation}, got ${liveInterfoldImplementation}`,
    );
  }
  const liveBondingImplementation = await proxyImplementation(
    ethers,
    plan.bondingProxy,
  );
  if (
    liveBondingImplementation.toLowerCase() !==
    plan.bondingImplementation.toLowerCase()
  ) {
    throw new Error(
      `BondingRegistry implementation: expected ${plan.bondingImplementation}, got ${liveBondingImplementation}`,
    );
  }
  if (!(await interfold.requestsPaused())) {
    throw new Error("E3 requests are already enabled");
  }
  const activeE3Count = await interfold.activeE3Count();
  if (activeE3Count !== 0n) {
    throw new Error(`Interfold still has ${activeE3Count} active E3s`);
  }
  const unreleasedCommittees = await registry.unreleasedCommitteeCount();
  if (unreleasedCommittees !== 0n) {
    throw new Error(
      `CiphernodeRegistry still has ${unreleasedCommittees} unreleased committees`,
    );
  }
  const bonding = await ethers.getContractAt(
    "BondingRegistry",
    plan.bondingProxy,
  );
  const nodeRelease = await ethers.getContractAt(
    "NodeReleaseRegistry",
    plan.nodeReleaseRegistry,
  );
  const configuredNodeRelease = await interfold.nodeReleaseRegistry();
  if (
    configuredNodeRelease.toLowerCase() !==
    plan.nodeReleaseRegistry.toLowerCase()
  ) {
    throw new Error(
      `interfold.nodeReleaseRegistry: expected ${plan.nodeReleaseRegistry}, got ${configuredNodeRelease}`,
    );
  }
  const requiredActiveNodes = config.interfold.committeeThresholds.reduce(
    (maximum, threshold) => {
      const total = BigInt(threshold.total);
      return total > maximum ? total : maximum;
    },
    0n,
  );
  const activeNodes = await bonding.numActiveOperators();
  if (activeNodes < requiredActiveNodes) {
    throw new Error(
      `Only ${activeNodes} release-ready operators are active; ${requiredActiveNodes} are required by the largest committee configuration`,
    );
  }
  await assertRefreshedOwnerCapacity(bonding, requiredActiveNodes);
  const requiredProtocolVersion = await nodeRelease.requiredProtocolVersion();
  const requiredNodeGeneration = await nodeRelease.requiredNodeGeneration();
  if (
    requiredProtocolVersion !== BigInt(plan.nodeRelease.protocolVersion) ||
    requiredNodeGeneration !== BigInt(plan.nodeRelease.nodeGeneration)
  ) {
    throw new Error(
      `node release policy changed after validation: expected protocol ${plan.nodeRelease.protocolVersion}, generation ${plan.nodeRelease.nodeGeneration}; got protocol ${requiredProtocolVersion}, generation ${requiredNodeGeneration}`,
    );
  }
  const configuredProvider = await registry.randomnessProvider();
  if (configuredProvider === ethers.ZeroAddress) {
    throw new Error("CiphernodeRegistry has no randomness provider");
  }
  if (
    configuredProvider.toLowerCase() !== plan.randomnessProvider.toLowerCase()
  ) {
    throw new Error(
      `registry.randomnessProvider: expected ${plan.randomnessProvider}, got ${configuredProvider}`,
    );
  }
  await requireContract(
    ethers.provider,
    configuredProvider,
    "randomness provider",
  );
  const provider = await ethers.getContractAt(
    "ChainlinkVrfRandomnessProvider",
    configuredProvider,
  );
  for (const [label, actual, expected] of [
    ["provider.owner", await provider.owner(), config.protocolOwner],
    [
      "provider.requester",
      await provider.requester(),
      deployment.ciphernodeRegistry,
    ],
    [
      "provider.coordinator",
      await provider.s_vrfCoordinator(),
      randomness.coordinator,
    ],
    [
      "provider.subscriptionId",
      await provider.subscriptionId(),
      randomness.subscriptionId,
    ],
    ["provider.keyHash", await provider.keyHash(), randomness.keyHash],
    [
      "provider.requestConfirmations",
      await provider.requestConfirmations(),
      randomness.requestConfirmations,
    ],
    [
      "provider.callbackGasLimit",
      await provider.callbackGasLimit(),
      randomness.callbackGasLimit,
    ],
    [
      "provider.nativePayment",
      await provider.nativePayment(),
      randomness.nativePayment,
    ],
    [
      "provider.minimumSubscriptionBalance",
      await provider.minimumSubscriptionBalance(),
      randomness.minimumSubscriptionBalance,
    ],
  ] as const) {
    if (String(actual).toLowerCase() !== String(expected).toLowerCase()) {
      throw new Error(`${label}: expected ${expected}, got ${actual}`);
    }
  }
  const liveRandomnessFee = (await interfold.getPricingConfig())
    .randomnessFlatFee;
  if (liveRandomnessFee !== BigInt(plan.randomnessFlatFee)) {
    throw new Error(
      `interfold.pricing.randomnessFlatFee: expected ${plan.randomnessFlatFee}, got ${liveRandomnessFee}`,
    );
  }
  const liveRequestTimeout = await registry.randomnessRequestTimeout();
  if (liveRequestTimeout !== BigInt(randomness.requestTimeout)) {
    throw new Error(
      `registry.randomnessRequestTimeout: expected ${randomness.requestTimeout}, got ${liveRequestTimeout}`,
    );
  }
  await assertVrfSubscription(ethers, effectiveConfig, configuredProvider);

  const txs: SafeTransaction[] = [
    safeTx(
      deployment.interfold,
      interfold.interface.encodeFunctionData("setRequestsPaused", [false]),
    ),
  ];
  const rawBatchFile = resumeBatchPath(config.name);
  const batch = governanceBatch(config, txs);
  batch.meta.name = `${config.name} VRF sortition resume`;
  batch.meta.description =
    "Enable E3 requests after the VRF upgrade was validated and every ciphernode was restarted.";
  writeJson(rawBatchFile, batch);

  let safeBuilderFile: string | undefined;
  if (config.governance) {
    safeBuilderFile = governanceSafeBuilderPath({
      ...config,
      name: `${config.name}.vrf-sortition.resume`,
    });
    const safeBatch = aragonAdminSafeBatch(config, txs);
    safeBatch.meta.name = `${config.name} VRF sortition resume`;
    writeJson(safeBuilderFile, safeBatch);
  }

  if (hasFlag("propose-safe")) {
    const proposalTransactions = config.governance
      ? aragonAdminSafeTransactions(config, txs)
      : txs;
    await proposeSafeBatch(
      config,
      proposalTransactions,
      config.governance?.proposerSafe ?? config.safe,
    );
  }

  console.log(`
VRF sortition resume prepared
  provider:                ${configuredProvider}
  restart acknowledged:   yes
  subscription:            funded and configured
  governance batch:        ${rawBatchFile}
  Aragon Safe batch:       ${safeBuilderFile ?? "(not configured)"}
`);
}

prepareVrfSortitionResume().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
