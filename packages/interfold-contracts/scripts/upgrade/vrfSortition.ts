// SPDX-License-Identifier: LGPL-3.0-only
import path from "node:path";

import { connect, hasFlag } from "../protocol/cli";
import { proxyAdminInterface } from "../protocol/constants";
import {
  deploymentPath,
  governanceSafeBuilderPath,
  protocolDir,
  readJson,
  repoRelativePath,
  writeJson,
} from "../protocol/files";
import {
  currentNodeRelease,
  deployNodeReleaseRegistry,
} from "../protocol/nodeRelease";
import {
  assertVrfSubscription,
  buildRandomnessTransactions,
  deployRandomnessProvider,
  requireRandomnessConfig,
} from "../protocol/randomness";
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
  VrfSortitionUpgradePlan,
} from "../protocol/types";
import {
  assertExitTiming,
  loadConfig,
  requireContract,
} from "../protocol/values";
import { deployUpgradeImplementation } from "./safeProxyUpgrade";

function planPath(config: ProtocolConfigFile): string {
  return path.join(protocolDir, `${config.name}.vrf-sortition.upgrade.json`);
}

function batchPath(config: ProtocolConfigFile): string {
  return path.join(
    protocolDir,
    `${config.name}.vrf-sortition.upgrade.safe.json`,
  );
}

async function requireProxyAdminOwner(
  ethers: any,
  proxyAdmin: string,
  expectedOwner: string,
  label: string,
): Promise<void> {
  await requireContract(ethers.provider, proxyAdmin, label);
  const admin = await ethers.getContractAt("ProxyAdmin", proxyAdmin);
  const actualOwner = await admin.owner();
  if (actualOwner.toLowerCase() !== expectedOwner.toLowerCase()) {
    throw new Error(
      `${label} owner mismatch: expected ${expectedOwner}, got ${actualOwner}`,
    );
  }
}

function upgradeTransaction(
  proxyAdmin: string,
  proxy: string,
  implementation: string,
): SafeTransaction {
  return safeTx(
    proxyAdmin,
    proxyAdminInterface.encodeFunctionData("upgradeAndCall", [
      proxy,
      implementation,
      "0x",
    ]),
  );
}

export async function prepareVrfSortitionUpgrade(): Promise<void> {
  const { ethers } = await connect();
  const config = loadConfig();
  const randomnessConfig = requireRandomnessConfig(config);
  const deployment = readJson<ProtocolDeployment>(deploymentPath(config));
  const network = await ethers.provider.getNetwork();
  if (Number(network.chainId) !== deployment.chainId) {
    throw new Error("Connected to the wrong network for this deployment file");
  }

  await Promise.all([
    requireContract(
      ethers.provider,
      deployment.ciphernodeRegistry,
      "ciphernode registry proxy",
    ),
    requireContract(ethers.provider, deployment.interfold, "Interfold proxy"),
    requireProxyAdminOwner(
      ethers,
      deployment.ciphernodeRegistryProxyAdmin,
      config.protocolOwner,
      "ciphernode registry ProxyAdmin",
    ),
    requireProxyAdminOwner(
      ethers,
      deployment.interfoldProxyAdmin,
      config.protocolOwner,
      "Interfold ProxyAdmin",
    ),
    requireProxyAdminOwner(
      ethers,
      config.bondingRegistryProxyAdmin,
      config.protocolOwner,
      "BondingRegistry ProxyAdmin",
    ),
    assertVrfSubscription(ethers, config),
  ]);

  const interfold = await ethers.getContractAt(
    "Interfold",
    deployment.interfold,
  );
  const registry = await ethers.getContractAt(
    "CiphernodeRegistryOwnable",
    deployment.ciphernodeRegistry,
  );
  if (!(await interfold.requestsPaused())) {
    throw new Error("Pause E3 requests before preparing the VRF upgrade");
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
  const liveBondingRegistry = await registry.bondingRegistry();
  await requireContract(
    ethers.provider,
    liveBondingRegistry,
    "live bonding registry",
  );
  if (
    liveBondingRegistry.toLowerCase() !==
    config.bondingRegistryProxy.toLowerCase()
  ) {
    throw new Error(
      `Configured BondingRegistry proxy ${config.bondingRegistryProxy} does not match the live registry binding ${liveBondingRegistry}`,
    );
  }
  const bondingRegistry = await ethers.getContractAt(
    "BondingRegistry",
    liveBondingRegistry,
  );
  assertExitTiming(
    await bondingRegistry.exitDelay(),
    await registry.sortitionSubmissionWindow(),
    BigInt(randomnessConfig.requestTimeout),
    "Live protocol",
  );

  const [operator] = await ethers.getSigners();
  const registryUpgrade = await deployUpgradeImplementation(
    ethers,
    operator,
    "ciphernodeRegistry",
    deployment,
  );
  const interfoldUpgrade = await deployUpgradeImplementation(
    ethers,
    operator,
    "interfold",
    deployment,
  );
  const bondingUpgrade = await deployUpgradeImplementation(
    ethers,
    operator,
    "bondingRegistry",
    deployment,
  );
  if (!registryUpgrade.sortitionLibrary) {
    throw new Error("Registry sortition library was not deployed");
  }
  if (!interfoldUpgrade.lifecycleLibrary || !interfoldUpgrade.pricingLibrary) {
    throw new Error("Interfold libraries were not deployed");
  }
  if (
    !bondingUpgrade.assetLibrary ||
    !bondingUpgrade.eligibilityLibrary ||
    !bondingUpgrade.slashingLibrary ||
    !bondingUpgrade.registrationLibrary ||
    !bondingUpgrade.ownershipLibrary
  ) {
    throw new Error("BondingRegistry libraries were not deployed");
  }
  let nodeReleaseDeployment: { address: string; interface: any };
  if (deployment.nodeReleaseRegistry) {
    await requireContract(
      ethers.provider,
      deployment.nodeReleaseRegistry,
      "recorded node release registry",
    );
    const existingNodeRelease = await ethers.getContractAt(
      "NodeReleaseRegistry",
      deployment.nodeReleaseRegistry,
    );
    for (const [label, actual, expected] of [
      ["owner", await existingNodeRelease.owner(), config.protocolOwner],
      [
        "BondingRegistry",
        await existingNodeRelease.bondingRegistry(),
        config.bondingRegistryProxy,
      ],
      [
        "CiphernodeRegistry",
        await existingNodeRelease.ciphernodeRegistry(),
        deployment.ciphernodeRegistry,
      ],
    ] as const) {
      if (String(actual).toLowerCase() !== String(expected).toLowerCase()) {
        throw new Error(
          `Recorded NodeReleaseRegistry ${label} mismatch: expected ${expected}, got ${actual}`,
        );
      }
    }
    nodeReleaseDeployment = {
      address: deployment.nodeReleaseRegistry,
      interface: existingNodeRelease.interface,
    };
  } else {
    nodeReleaseDeployment = await deployNodeReleaseRegistry(
      ethers,
      config.protocolOwner,
      config.bondingRegistryProxy,
      deployment.ciphernodeRegistry,
    );
  }
  const nodeRelease = currentNodeRelease();
  const randomness = await deployRandomnessProvider(
    ethers,
    operator,
    config,
    deployment.ciphernodeRegistry,
  );

  const txs: SafeTransaction[] = [
    upgradeTransaction(
      deployment.ciphernodeRegistryProxyAdmin,
      deployment.ciphernodeRegistry,
      registryUpgrade.implementation,
    ),
    upgradeTransaction(
      deployment.interfoldProxyAdmin,
      deployment.interfold,
      interfoldUpgrade.implementation,
    ),
    upgradeTransaction(
      config.bondingRegistryProxyAdmin,
      config.bondingRegistryProxy,
      bondingUpgrade.implementation,
    ),
    safeTx(
      deployment.interfold,
      interfold.interface.encodeFunctionData("setNodeReleaseRegistry", [
        nodeReleaseDeployment.address,
      ]),
    ),
    safeTx(
      nodeReleaseDeployment.address,
      nodeReleaseDeployment.interface.encodeFunctionData(
        "setRequiredNodeRelease",
        [nodeRelease.protocolVersion, nodeRelease.nodeGeneration],
      ),
    ),
    safeTx(
      deployment.interfold,
      interfold.interface.encodeFunctionData("setRandomnessFlatFee", [
        BigInt(config.interfold.pricing.randomnessFlatFee),
      ]),
    ),
    ...buildRandomnessTransactions(
      config,
      randomness.randomnessProvider,
      deployment.ciphernodeRegistry,
      registry.interface,
      randomness.randomnessProviderOwnershipAcceptanceRequired,
    ),
  ];

  const rawBatchFile = batchPath(config);
  const batch = governanceBatch(config, txs);
  batch.meta.name = `${config.name} VRF sortition upgrade`;
  batch.meta.description =
    "Upgrade committee sortition to Chainlink VRF and keep E3 requests paused until every ciphernode restarts.";
  writeJson(rawBatchFile, batch);

  let safeBuilderFile: string | undefined;
  if (config.governance) {
    safeBuilderFile = governanceSafeBuilderPath({
      ...config,
      name: `${config.name}.vrf-sortition.upgrade`,
    });
    const safeBatch = aragonAdminSafeBatch(config, txs);
    safeBatch.meta.name = `${config.name} VRF sortition upgrade`;
    writeJson(safeBuilderFile, safeBatch);
  }

  const plan: VrfSortitionUpgradePlan = {
    name: config.name,
    operator: await operator.getAddress(),
    protocolOwner: config.protocolOwner,
    registryProxy: deployment.ciphernodeRegistry,
    registryProxyAdmin: deployment.ciphernodeRegistryProxyAdmin,
    registryImplementation: registryUpgrade.implementation,
    sortitionLibrary: registryUpgrade.sortitionLibrary,
    interfoldProxy: deployment.interfold,
    interfoldProxyAdmin: deployment.interfoldProxyAdmin,
    interfoldImplementation: interfoldUpgrade.implementation,
    lifecycleLibrary: interfoldUpgrade.lifecycleLibrary,
    pricingLibrary: interfoldUpgrade.pricingLibrary,
    bondingProxy: config.bondingRegistryProxy,
    bondingProxyAdmin: config.bondingRegistryProxyAdmin,
    bondingImplementation: bondingUpgrade.implementation,
    bondingAssetLibrary: bondingUpgrade.assetLibrary,
    bondingEligibilityLibrary: bondingUpgrade.eligibilityLibrary,
    bondingSlashingLibrary: bondingUpgrade.slashingLibrary,
    bondingRegistrationLibrary: bondingUpgrade.registrationLibrary,
    bondingOwnershipLibrary: bondingUpgrade.ownershipLibrary,
    nodeReleaseRegistry: nodeReleaseDeployment.address,
    nodeRelease,
    randomnessProvider: randomness.randomnessProvider,
    randomness: { ...randomnessConfig },
    randomnessFlatFee: config.interfold.pricing.randomnessFlatFee,
    randomnessProviderOwnershipAcceptanceRequired:
      randomness.randomnessProviderOwnershipAcceptanceRequired,
    safeTransactions: repoRelativePath(rawBatchFile),
    governanceSafeBuilder: safeBuilderFile
      ? repoRelativePath(safeBuilderFile)
      : undefined,
  };

  if (hasFlag("propose-safe")) {
    const proposalTransactions = config.governance
      ? aragonAdminSafeTransactions(config, txs)
      : txs;
    plan.safeProposal = await proposeSafeBatch(
      config,
      proposalTransactions,
      config.governance?.proposerSafe ?? config.safe,
    );
  }
  writeJson(planPath(config), plan);

  console.log(`
VRF sortition upgrade prepared
  registry implementation: ${plan.registryImplementation}
  Interfold implementation:${plan.interfoldImplementation}
  Bonding implementation: ${plan.bondingImplementation}
  node release registry:  ${plan.nodeReleaseRegistry}
  randomness provider:      ${plan.randomnessProvider}
  governance batch:         ${plan.safeTransactions}
  Aragon Safe batch:        ${plan.governanceSafeBuilder ?? "(not configured)"}
  transactions:             ${txs.length}
  requests remain paused after execution
`);
}

prepareVrfSortitionUpgrade().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
