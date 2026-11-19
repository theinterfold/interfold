// SPDX-License-Identifier: LGPL-3.0-only
import path from "node:path";

import { connect } from "../protocol/cli";
import {
  deploymentPath,
  protocolDir,
  readJson,
  writeJson,
} from "../protocol/files";
import {
  assertVrfSubscription,
  assertVrfUpgradePlanMatchesDeployment,
  requirePlannedRandomnessConfig,
} from "../protocol/randomness";
import type {
  ProtocolDeployment,
  VrfSortitionUpgradePlan,
} from "../protocol/types";
import { loadConfig, requireContract } from "../protocol/values";
import {
  assertDkgPublicationLibraryLink,
  proxyImplementation,
} from "./safeProxyUpgrade";

function assertEqual(label: string, actual: unknown, expected: unknown): void {
  if (String(actual).toLowerCase() !== String(expected).toLowerCase()) {
    throw new Error(`${label}: expected ${expected}, got ${actual}`);
  }
  console.log(`  ok ${label}`);
}

export async function validateVrfSortitionUpgrade(): Promise<void> {
  const { ethers } = await connect();
  const config = loadConfig();
  const deploymentFile = deploymentPath(config);
  const deployment = readJson<ProtocolDeployment>(deploymentFile);
  const plan = readJson<VrfSortitionUpgradePlan>(
    path.join(protocolDir, `${config.name}.vrf-sortition.upgrade.json`),
  );
  const network = await ethers.provider.getNetwork();
  assertVrfUpgradePlanMatchesDeployment(
    config,
    deployment,
    plan,
    network.chainId,
  );
  const randomness = requirePlannedRandomnessConfig(config, plan);
  const effectiveConfig = { ...config, randomness };

  for (const [label, target] of [
    ["registry implementation", plan.registryImplementation],
    ["sortition library", plan.sortitionLibrary],
    ["Interfold implementation", plan.interfoldImplementation],
    ["lifecycle library", plan.lifecycleLibrary],
    ["pricing library", plan.pricingLibrary],
    ["BondingRegistry implementation", plan.bondingImplementation],
    ["bonding asset library", plan.bondingAssetLibrary],
    ["bonding eligibility library", plan.bondingEligibilityLibrary],
    ["bonding slashing library", plan.bondingSlashingLibrary],
    ["bonding registration library", plan.bondingRegistrationLibrary],
    ["bonding ownership library", plan.bondingOwnershipLibrary],
    ["node release registry", plan.nodeReleaseRegistry],
    ["randomness provider", plan.randomnessProvider],
  ] as const) {
    await requireContract(ethers.provider, target, label);
  }
  if (plan.dkgPublicationLibrary) {
    await assertDkgPublicationLibraryLink(
      ethers.provider,
      plan.registryImplementation,
      plan.dkgPublicationLibrary,
    );
  }

  assertEqual(
    "registry implementation",
    await proxyImplementation(ethers, plan.registryProxy),
    plan.registryImplementation,
  );
  assertEqual(
    "Interfold implementation",
    await proxyImplementation(ethers, plan.interfoldProxy),
    plan.interfoldImplementation,
  );
  assertEqual(
    "BondingRegistry implementation",
    await proxyImplementation(ethers, plan.bondingProxy),
    plan.bondingImplementation,
  );

  const registry = await ethers.getContractAt(
    "CiphernodeRegistryOwnable",
    plan.registryProxy,
  );
  const interfold = await ethers.getContractAt(
    "Interfold",
    plan.interfoldProxy,
  );
  const provider = await ethers.getContractAt(
    "ChainlinkVrfRandomnessProvider",
    plan.randomnessProvider,
  );
  const bonding = await ethers.getContractAt(
    "BondingRegistry",
    plan.bondingProxy,
  );
  const nodeRelease = await ethers.getContractAt(
    "NodeReleaseRegistry",
    plan.nodeReleaseRegistry,
  );
  for (const [label, actual, expected] of [
    [
      "registry.randomnessProvider",
      await registry.randomnessProvider(),
      plan.randomnessProvider,
    ],
    [
      "registry.randomnessRequestTimeout",
      await registry.randomnessRequestTimeout(),
      randomness.requestTimeout,
    ],
    ["provider.owner", await provider.owner(), config.protocolOwner],
    ["provider.requester", await provider.requester(), plan.registryProxy],
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
    assertEqual(label, actual, expected);
  }

  if (!(await interfold.requestsPaused())) {
    throw new Error("Interfold requests must remain paused during validation");
  }
  for (const [label, actual, expected] of [
    [
      "interfold.nodeReleaseRegistry",
      await interfold.nodeReleaseRegistry(),
      plan.nodeReleaseRegistry,
    ],
    ["nodeRelease.owner", await nodeRelease.owner(), config.protocolOwner],
    [
      "nodeRelease.bondingRegistry",
      await nodeRelease.bondingRegistry(),
      plan.bondingProxy,
    ],
    [
      "nodeRelease.ciphernodeRegistry",
      await nodeRelease.ciphernodeRegistry(),
      plan.registryProxy,
    ],
    [
      "nodeRelease.requiredProtocolVersion",
      await nodeRelease.requiredProtocolVersion(),
      plan.nodeRelease.protocolVersion,
    ],
    [
      "nodeRelease.requiredNodeGeneration",
      await nodeRelease.requiredNodeGeneration(),
      plan.nodeRelease.nodeGeneration,
    ],
  ] as const) {
    assertEqual(label, actual, expected);
  }
  console.log(
    `  ok release-ready active operators: ${await bonding.numActiveOperators()}`,
  );
  assertEqual("interfold.activeE3Count", await interfold.activeE3Count(), 0);
  assertEqual(
    "interfold.pricing.randomnessFlatFee",
    (await interfold.getPricingConfig()).randomnessFlatFee,
    BigInt(plan.randomnessFlatFee),
  );
  assertEqual(
    "registry.unreleasedCommitteeCount",
    await registry.unreleasedCommitteeCount(),
    0,
  );

  await assertVrfSubscription(ethers, effectiveConfig, plan.randomnessProvider);
  console.log("  ok VRF subscription consumer");

  writeJson(deploymentFile, {
    ...deployment,
    registrySortitionLib: plan.sortitionLibrary,
    dkgPublicationLib: plan.dkgPublicationLibrary,
    ciphernodeRegistryImplementation: plan.registryImplementation,
    interfoldImplementation: plan.interfoldImplementation,
    interfoldLifecycle: plan.lifecycleLibrary,
    interfoldPricing: plan.pricingLibrary,
    bondingRegistryImplementation: plan.bondingImplementation,
    bondingAssetLib: plan.bondingAssetLibrary,
    bondingEligibilityLib: plan.bondingEligibilityLibrary,
    bondingSlashingLib: plan.bondingSlashingLibrary,
    bondingRegistrationLib: plan.bondingRegistrationLibrary,
    bondingOwnershipLib: plan.bondingOwnershipLibrary,
    nodeReleaseRegistry: plan.nodeReleaseRegistry,
    randomnessProvider: plan.randomnessProvider,
    randomness,
    randomnessProviderOwnershipAcceptanceRequired: false,
  });
  console.log(`VRF sortition upgrade validated; updated ${deploymentFile}`);
  console.log(
    "E3 requests remain paused. Restart every ciphernode before preparing the resume transaction.",
  );
}

validateVrfSortitionUpgrade().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
