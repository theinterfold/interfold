// SPDX-License-Identifier: LGPL-3.0-only
import { ethers as ethersLib } from "ethers";

import { connect } from "../protocol/cli";
import { proxyAdminInterface } from "../protocol/constants";
import { deploymentPath, readJson } from "../protocol/files";
import {
  assertVrfSubscription,
  buildRandomnessTransactions,
  deployRandomnessProvider,
  readOptionalPendingRequestCount,
  requireExistingRandomnessConfig,
} from "../protocol/randomness";
import { aragonAdminSafeTransactions, safeTx } from "../protocol/safe";
import {
  buildSlashingManagerMigrationTransactions,
  deploySlashingManagerReplacement,
} from "../protocol/serviceMigration";
import type {
  ProtocolConfigFile,
  ProtocolDeployment,
  SafeTransaction,
} from "../protocol/types";
import { loadConfig } from "../protocol/values";
import {
  deployUpgradeImplementation,
  proxyImplementation,
} from "./safeProxyUpgrade";

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

function equal(actual: unknown, expected: unknown, label: string): void {
  if (String(actual).toLowerCase() !== String(expected).toLowerCase()) {
    throw new Error(`${label}: expected ${expected}, got ${actual}`);
  }
}

async function requireAnvilMainnetFork(ethers: any): Promise<void> {
  const network = await ethers.provider.getNetwork();
  const client = String(
    await ethers.provider.send("web3_clientVersion", []),
  ).toLowerCase();
  if (
    process.env.CONFIRM_MAINNET_FORK !== "1" ||
    network.chainId !== 1n ||
    !client.includes("anvil")
  ) {
    throw new Error(
      "This simulation runs only on an Anvil mainnet fork with CONFIRM_MAINNET_FORK=1",
    );
  }
}

export async function simulateServiceMigration(): Promise<void> {
  const { ethers } = await connect();
  await requireAnvilMainnetFork(ethers);
  const config = loadConfig();
  if (!config.governance) {
    throw new Error("Aragon governance is required for this simulation");
  }
  const deployment = readJson<ProtocolDeployment>(deploymentPath(config));
  const randomness = requireExistingRandomnessConfig(config, deployment);
  const effectiveConfig: ProtocolConfigFile = { ...config, randomness };
  const [deployer] = await ethers.getSigners();
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
    deployment.bondingRegistryProxy,
  );
  const previousManager = await ethers.getContractAt(
    "SlashingManager",
    deployment.slashingManager,
  );
  if (!(await interfold.requestsPaused())) {
    throw new Error("Mainnet-fork requests are not paused");
  }
  for (const [label, value] of [
    ["active E3 count", await interfold.activeE3Count()],
    ["unreleased committee count", await registry.unreleasedCommitteeCount()],
    ["unresolved committee count", await bonding.unresolvedCommitteeCount()],
    [
      "active slashing assignments",
      await previousManager.activeE3Assignments(),
    ],
    ["active bans", await previousManager.activeBanCount()],
  ] as const) {
    equal(value, 0n, label);
  }
  const previousPendingRequests = await readOptionalPendingRequestCount(
    ethers.provider,
    deployment.randomnessProvider,
  );
  if (previousPendingRequests !== undefined) {
    equal(previousPendingRequests, 0n, "pending randomness requests");
  }
  await assertVrfSubscription(
    ethers,
    effectiveConfig,
    deployment.randomnessProvider,
  );
  const [registeredOperators, activeOperators, root] = await Promise.all([
    bonding.numRegisteredOperators(),
    bonding.numActiveOperators(),
    registry.root(),
  ]);
  equal(await registry.numCiphernodes(), registeredOperators, "operator count");

  const registryUpgrade = await deployUpgradeImplementation(
    ethers,
    deployer,
    "ciphernodeRegistry",
    deployment,
  );
  const interfoldUpgrade = await deployUpgradeImplementation(
    ethers,
    deployer,
    "interfold",
    deployment,
  );
  const bondingUpgrade = await deployUpgradeImplementation(
    ethers,
    deployer,
    "bondingRegistry",
    deployment,
  );
  const refundUpgrade = await deployUpgradeImplementation(
    ethers,
    deployer,
    "e3RefundManager",
    deployment,
  );
  const replacementManager = await deploySlashingManagerReplacement(
    ethers,
    effectiveConfig,
  );
  const replacementRandomness = await deployRandomnessProvider(
    ethers,
    deployer,
    effectiveConfig,
    deployment.ciphernodeRegistry,
  );
  const slashingMigration = await buildSlashingManagerMigrationTransactions(
    ethers,
    effectiveConfig,
    deployment,
    replacementManager,
  );
  const actions: SafeTransaction[] = [
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
      deployment.bondingRegistryProxyAdmin,
      deployment.bondingRegistryProxy,
      bondingUpgrade.implementation,
    ),
    upgradeTransaction(
      deployment.e3RefundManagerProxyAdmin,
      deployment.e3RefundManager,
      refundUpgrade.implementation,
    ),
    ...slashingMigration.transactions,
    ...buildRandomnessTransactions(
      effectiveConfig,
      replacementRandomness.randomnessProvider,
      deployment.ciphernodeRegistry,
      registry.interface,
      replacementRandomness.randomnessProviderOwnershipAcceptanceRequired,
    ),
  ];
  const [governanceCall] = aragonAdminSafeTransactions(config, actions);
  const proposer = config.governance.proposerSafe;
  await ethers.provider.send("anvil_impersonateAccount", [proposer]);
  await ethers.provider.send("anvil_setBalance", [
    proposer,
    ethersLib.toBeHex(ethersLib.parseEther("100")),
  ]);
  const proposerSigner = await ethers.getSigner(proposer);
  await (
    await proposerSigner.sendTransaction({
      to: governanceCall.to,
      data: governanceCall.data,
      value: governanceCall.value,
      gasLimit: 55_000_000,
    })
  ).wait();

  equal(
    await proxyImplementation(ethers, deployment.ciphernodeRegistry),
    registryUpgrade.implementation,
    "registry implementation",
  );
  equal(
    await proxyImplementation(ethers, deployment.interfold),
    interfoldUpgrade.implementation,
    "Interfold implementation",
  );
  equal(
    await proxyImplementation(ethers, deployment.bondingRegistryProxy),
    bondingUpgrade.implementation,
    "bonding implementation",
  );
  equal(
    await proxyImplementation(ethers, deployment.e3RefundManager),
    refundUpgrade.implementation,
    "refund implementation",
  );
  equal(await registry.root(), root, "registry root");
  equal(
    await registry.numCiphernodes(),
    registeredOperators,
    "registry operators",
  );
  equal(
    await bonding.numRegisteredOperators(),
    registeredOperators,
    "bonding operators",
  );
  equal(
    await bonding.numActiveOperators(),
    activeOperators,
    "active operators",
  );
  for (const [label, actual, expected] of [
    [
      "Interfold manager",
      await interfold.slashingManager(),
      replacementManager.manager,
    ],
    [
      "registry manager",
      await registry.slashingManager(),
      replacementManager.manager,
    ],
    [
      "bonding manager",
      await bonding.slashingManager(),
      replacementManager.manager,
    ],
    [
      "registry randomness provider",
      await registry.randomnessProvider(),
      replacementRandomness.randomnessProvider,
    ],
  ] as const) {
    equal(actual, expected, label);
  }
  equal(
    await bonding.isAuthorizedSlashingManager(deployment.slashingManager),
    false,
    "previous manager authorization",
  );
  await assertVrfSubscription(
    ethers,
    effectiveConfig,
    replacementRandomness.randomnessProvider,
  );

  console.log(`
Mainnet-fork service migration passed
  registered operators: ${registeredOperators}
  active operators:     ${activeOperators}
  registry root:        ${root}
  slashing manager:     ${replacementManager.manager}
  VRF provider:         ${replacementRandomness.randomnessProvider}
  VRF subscription:     ${randomness.subscriptionId} (reused)
  governance actions:   ${actions.length}
`);
}

simulateServiceMigration().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
