// SPDX-License-Identifier: LGPL-3.0-only
import { ethers as ethersLib } from "ethers";

import { connect } from "./cli";
import { deploymentPath, readJson } from "./files";
import { currentNodeRelease } from "./nodeRelease";
import { assertVrfSubscription, requireRandomnessConfig } from "./randomness";
import type { ProtocolDeployment } from "./types";
import { checkExcludedAccounts, loadConfig, requireContract } from "./values";

function assertEqual(label: string, actual: unknown, expected: unknown): void {
  if (String(actual).toLowerCase() !== String(expected).toLowerCase()) {
    throw new Error(`${label}: expected ${expected}, got ${actual}`);
  }
  console.log(`  ok ${label}`);
}

async function assertStruct(
  label: string,
  actualPromise: Promise<Record<string, unknown>>,
  expected: Record<string, unknown>,
): Promise<void> {
  const actual = await actualPromise;
  for (const [field, value] of Object.entries(expected)) {
    assertEqual(`${label}.${field}`, actual[field], value);
  }
}

export async function actionValidate(): Promise<void> {
  const { ethers } = await connect();
  const config = loadConfig();
  const deployment = readJson<ProtocolDeployment>(deploymentPath(config));
  const network = await ethers.provider.getNetwork();
  if (Number(network.chainId) !== deployment.chainId) {
    throw new Error("Connected to the wrong network for this deployment file");
  }

  const ticket = await ethers.getContractAt(
    "InterfoldTicketToken",
    deployment.ticketToken,
  );
  const registry = await ethers.getContractAt(
    "CiphernodeRegistryOwnable",
    deployment.ciphernodeRegistry,
  );
  const interfold = await ethers.getContractAt(
    "Interfold",
    deployment.interfold,
  );
  const refund = await ethers.getContractAt(
    "E3RefundManager",
    deployment.e3RefundManager,
  );
  const bonding = await ethers.getContractAt(
    "BondingRegistry",
    deployment.bondingRegistryProxy,
  );
  const slashing = await ethers.getContractAt(
    "SlashingManager",
    deployment.slashingManager,
  );
  const checkpoints = await ethers.getContractAt(
    "BondedCheckpoints",
    deployment.bondedCheckpoints,
  );
  const randomnessConfig = requireRandomnessConfig(config);
  const randomnessProvider = await ethers.getContractAt(
    "ChainlinkVrfRandomnessProvider",
    deployment.randomnessProvider,
  );
  const nodeReleaseRegistry = await ethers.getContractAt(
    "NodeReleaseRegistry",
    deployment.nodeReleaseRegistry,
  );
  const nodeRelease = currentNodeRelease();

  const proxyAdmin = (target: string) =>
    new ethersLib.Contract(
      target,
      ["function owner() view returns (address)"],
      ethers.provider,
    );

  for (const [label, address] of [
    ["bondingAssetLib", deployment.bondingAssetLib],
    ["bondingEligibilityLib", deployment.bondingEligibilityLib],
    ["bondingSlashingLib", deployment.bondingSlashingLib],
    ["slashingEvidenceLib", deployment.slashingEvidenceLib],
    ["registrySortitionLib", deployment.registrySortitionLib],
    ["interfoldLifecycle", deployment.interfoldLifecycle],
    ["interfoldPricing", deployment.interfoldPricing],
    ["bondedCheckpoints", deployment.bondedCheckpoints],
    ["randomnessProvider", deployment.randomnessProvider],
    ["nodeReleaseRegistry", deployment.nodeReleaseRegistry],
  ] as const) {
    if ((await ethers.provider.getCode(address)) === "0x") {
      throw new Error(`${label}: no contract at ${address}`);
    }
    console.log(`  ok ${label}`);
  }

  const checks: Array<[string, Promise<unknown>, unknown]> = [
    ["ticket.owner", ticket.owner(), config.protocolOwner],
    ["ticket.registry", ticket.registry(), deployment.bondingRegistryProxy],
    ["ticket.underlying", ticket.underlying(), config.ticketUnderlyingToken],
    ["ticket.decimals", ticket.decimals(), config.bonding.ticketTokenDecimals],
    [
      "ticket.registryLocked",
      ticket.registryLocked(),
      config.ticketToken.lockRegistry,
    ],
    ["registry.owner", registry.owner(), config.protocolOwner],
    [
      "registry.randomnessProvider",
      registry.randomnessProvider(),
      deployment.randomnessProvider,
    ],
    [
      "registry.randomnessRequestTimeout",
      registry.randomnessRequestTimeout(),
      randomnessConfig.requestTimeout,
    ],
    [
      "randomnessProvider.requester",
      randomnessProvider.requester(),
      deployment.ciphernodeRegistry,
    ],
    [
      "randomnessProvider.coordinator",
      randomnessProvider.s_vrfCoordinator(),
      randomnessConfig.coordinator,
    ],
    [
      "randomnessProvider.subscriptionId",
      randomnessProvider.subscriptionId(),
      randomnessConfig.subscriptionId,
    ],
    [
      "randomnessProvider.keyHash",
      randomnessProvider.keyHash(),
      randomnessConfig.keyHash,
    ],
    [
      "randomnessProvider.requestConfirmations",
      randomnessProvider.requestConfirmations(),
      randomnessConfig.requestConfirmations,
    ],
    [
      "randomnessProvider.callbackGasLimit",
      randomnessProvider.callbackGasLimit(),
      randomnessConfig.callbackGasLimit,
    ],
    [
      "randomnessProvider.nativePayment",
      randomnessProvider.nativePayment(),
      randomnessConfig.nativePayment,
    ],
    [
      "randomnessProvider.minimumSubscriptionBalance",
      randomnessProvider.minimumSubscriptionBalance(),
      randomnessConfig.minimumSubscriptionBalance,
    ],
    [
      "randomnessProvider.owner",
      randomnessProvider.owner(),
      config.protocolOwner,
    ],
    ["registry.interfold", registry.interfold(), deployment.interfold],
    [
      "registry.bondingRegistry",
      registry.bondingRegistry(),
      deployment.bondingRegistryProxy,
    ],
    [
      "registry.slashingManager",
      registry.slashingManager(),
      deployment.slashingManager,
    ],
    ["interfold.owner", interfold.owner(), config.protocolOwner],
    [
      "interfold.nodeReleaseRegistry",
      interfold.nodeReleaseRegistry(),
      deployment.nodeReleaseRegistry,
    ],
    [
      "nodeReleaseRegistry.owner",
      nodeReleaseRegistry.owner(),
      config.protocolOwner,
    ],
    [
      "nodeReleaseRegistry.bondingRegistry",
      nodeReleaseRegistry.bondingRegistry(),
      deployment.bondingRegistryProxy,
    ],
    [
      "nodeReleaseRegistry.ciphernodeRegistry",
      nodeReleaseRegistry.ciphernodeRegistry(),
      deployment.ciphernodeRegistry,
    ],
    [
      "nodeReleaseRegistry.requiredProtocolVersion",
      nodeReleaseRegistry.requiredProtocolVersion(),
      nodeRelease.protocolVersion,
    ],
    [
      "nodeReleaseRegistry.requiredNodeGeneration",
      nodeReleaseRegistry.requiredNodeGeneration(),
      nodeRelease.nodeGeneration,
    ],
    ["interfold.feeToken", interfold.feeToken(), config.feeToken],
    [
      "interfold.feeTokenDecimals",
      interfold.feeTokenDecimals(),
      config.feeTokenDecimals,
    ],
    [
      "interfold.bondingRegistry",
      interfold.bondingRegistry(),
      deployment.bondingRegistryProxy,
    ],
    [
      "interfold.ciphernodeRegistry",
      interfold.ciphernodeRegistry(),
      deployment.ciphernodeRegistry,
    ],
    [
      "interfold.e3RefundManager",
      interfold.e3RefundManager(),
      deployment.e3RefundManager,
    ],
    [
      "interfold.slashingManager",
      interfold.slashingManager(),
      deployment.slashingManager,
    ],
    ["refund.owner", refund.owner(), config.protocolOwner],
    ["bonding.owner", bonding.owner(), config.protocolOwner],
    ["bonding.ticketToken", bonding.ticketToken(), deployment.ticketToken],
    ["bonding.ciphernodeBondToken", bonding.ciphernodeBondToken(), config.fold],
    ["bonding.ticketPrice", bonding.ticketPrice(), config.bonding.ticketPrice],
    [
      "bonding.requiredCiphernodeBond",
      bonding.requiredCiphernodeBond(),
      config.bonding.requiredCiphernodeBond,
    ],
    [
      "bonding.minTicketBalance",
      bonding.minTicketBalance(),
      config.bonding.minTicketBalance,
    ],
    ["bonding.exitDelay", bonding.exitDelay(), config.bonding.exitDelay],
    [
      "bonding.slashedFundsTreasury",
      bonding.slashedFundsTreasury(),
      config.slashedFundsTreasury,
    ],
    ["bonding.registry", bonding.registry(), deployment.ciphernodeRegistry],
    [
      "bonding.slashingManager",
      bonding.slashingManager(),
      deployment.slashingManager,
    ],
    [
      "registry.sortitionSubmissionWindow",
      registry.sortitionSubmissionWindow(),
      config.registry.sortitionSubmissionWindow,
    ],
    [
      "interfold.maxDuration",
      interfold.maxDuration(),
      config.interfold.maxDuration,
    ],
    [
      "interfold.markFailedGracePeriod",
      interfold.markFailedGracePeriod(),
      config.interfold.markFailedGracePeriod,
    ],
    ["interfold.requestsPaused", interfold.requestsPaused(), true],
    [
      "bondingRegistryProxyAdmin.owner",
      proxyAdmin(deployment.bondingRegistryProxyAdmin).owner(),
      config.protocolOwner,
    ],
    [
      "ciphernodeRegistryProxyAdmin.owner",
      proxyAdmin(deployment.ciphernodeRegistryProxyAdmin).owner(),
      config.protocolOwner,
    ],
    [
      "interfoldProxyAdmin.owner",
      proxyAdmin(deployment.interfoldProxyAdmin).owner(),
      config.protocolOwner,
    ],
    [
      "e3RefundManagerProxyAdmin.owner",
      proxyAdmin(deployment.e3RefundManagerProxyAdmin).owner(),
      config.protocolOwner,
    ],
    ["slashing.interfold", slashing.interfold(), deployment.interfold],
    [
      "slashing.bondingRegistry",
      slashing.bondingRegistry(),
      deployment.bondingRegistryProxy,
    ],
    [
      "slashing.ciphernodeRegistry",
      slashing.ciphernodeRegistry(),
      deployment.ciphernodeRegistry,
    ],
    [
      "slashing.e3RefundManager",
      slashing.e3RefundManager(),
      deployment.e3RefundManager,
    ],
    // The bonded-voting graph. `bonding.bondedCheckpoints` is the one configured reference; the
    // rest is fixed at construction and is checked so a pair deployed against the wrong registry
    // or the wrong token cannot pass validation.
    [
      "bonding.bondedCheckpoints",
      bonding.bondedCheckpoints(),
      deployment.bondedCheckpoints,
    ],
    [
      "bondedCheckpoints.registry",
      checkpoints.registry(),
      deployment.bondingRegistryProxy,
    ],
  ];

  // Only after `--action activate-voting`. Its constructor already enforces the token and registry
  // binding, so these read-backs confirm the deployment file names the contract that was built.
  if (deployment.bondedVotes) {
    const bondedVotes = await ethers.getContractAt(
      "BondedVotes",
      deployment.bondedVotes,
    );
    checks.push(
      ["bondedVotes.token", bondedVotes.token(), config.fold],
      [
        "bondedVotes.votesSource",
        bondedVotes.votesSource(),
        config.escrowVotesAdapter ?? config.fold,
      ],
      [
        "bondedVotes.checkpoints",
        bondedVotes.checkpoints(),
        deployment.bondedCheckpoints,
      ],
      [
        "bondedVotes.registry",
        bondedVotes.registry(),
        deployment.bondingRegistryProxy,
      ],
    );
  } else {
    console.log("  -- bondedVotes not deployed yet (--action activate-voting)");
  }

  // Verifier read-backs. Each is configured by a Safe transaction, so a dropped or reverted write
  // would otherwise leave the reference at address(0) with the deploy script still exiting zero.
  const bfvSchemeId = ethers.id("fhe.rs:BFV");
  // A read-back alone proves only that the address was stored. Interfold returns whatever was
  // configured, so an EOA or an undeployed address passes while being unusable when a receipt is
  // actually verified.
  for (const [label, address] of [
    ["verifiers.ciphertextVerifier", config.verifiers?.ciphertextVerifier],
    ["verifiers.decryptionVerifier", config.verifiers?.decryptionVerifier],
    ["verifiers.pkVerifier", config.verifiers?.pkVerifier],
  ] as const) {
    if (address) await requireContract(ethers.provider, address, label);
  }

  if (config.verifiers?.ciphertextVerifier) {
    checks.push([
      "interfold.getCiphertextVerifier(fhe.rs:BFV)",
      interfold.getCiphertextVerifier(bfvSchemeId),
      config.verifiers.ciphertextVerifier,
    ]);
  }
  if (config.verifiers?.decryptionVerifier) {
    checks.push([
      "interfold.getDecryptionVerifier(fhe.rs:BFV)",
      interfold.getDecryptionVerifier(bfvSchemeId),
      config.verifiers.decryptionVerifier,
    ]);
  }
  if (config.verifiers?.pkVerifier) {
    checks.push([
      "interfold.getPkVerifier(fhe.rs:BFV)",
      interfold.getPkVerifier(bfvSchemeId),
      config.verifiers.pkVerifier,
    ]);
  }

  for (const [label, actualPromise, expected] of checks) {
    const actual = await actualPromise;
    assertEqual(label, actual, expected);
  }

  await assertVrfSubscription(ethers, config, deployment.randomnessProvider);
  console.log("  ok randomnessProvider subscription consumer");

  await assertStruct("interfold.timeout", interfold.getTimeoutConfig(), {
    dkgWindow: config.interfold.timeoutConfig.dkgWindow,
    computeWindow: config.interfold.timeoutConfig.computeWindow,
    decryptionWindow: config.interfold.timeoutConfig.decryptionWindow,
  });
  await assertStruct("interfold.pricing", interfold.getPricingConfig(), {
    ...config.interfold.pricing,
  });
  await assertStruct("refund.workAllocation", refund.getWorkAllocation(), {
    committeeFormationBps: 1000,
    dkgBps: 4000,
    decryptionBps: 4500,
    protocolBps: 500,
    successSlashedNodeBps: 5000,
  });

  for (const threshold of config.interfold.committeeThresholds) {
    assertEqual(
      `interfold.committeeThresholds(${threshold.size}).quorum`,
      await interfold.committeeThresholds(threshold.size, 0),
      threshold.quorum,
    );
    assertEqual(
      `interfold.committeeThresholds(${threshold.size}).total`,
      await interfold.committeeThresholds(threshold.size, 1),
      threshold.total,
    );
  }

  await requireContract(
    ethers.provider,
    deployment.initialE3Program,
    "initialE3Program",
  );
  if (!(await interfold.e3Programs(deployment.initialE3Program))) {
    throw new Error(
      `E3 Program is not registered: ${deployment.initialE3Program}`,
    );
  }
  console.log(`  ok interfold.e3Programs(${deployment.initialE3Program})`);

  const encryptionSchemeId = ethers.id("fhe.rs:BFV");
  for (const [label, actualPromise, expected] of [
    [
      "interfold.decryptionVerifier",
      interfold.decryptionVerifiers(encryptionSchemeId),
      deployment.decryptionVerifier ?? config.verifiers?.decryptionVerifier,
    ],
    [
      "interfold.pkVerifier",
      interfold.pkVerifiers(encryptionSchemeId),
      deployment.pkVerifier ?? config.verifiers?.pkVerifier,
    ],
    [
      "registry.dkgFoldAttestationVerifier",
      registry.dkgFoldAttestationVerifier(),
      deployment.dkgFoldAttestationVerifier ??
        config.verifiers?.dkgFoldAttestationVerifier,
    ],
    [
      "interfold.ciphertextVerifier",
      interfold.getCiphertextVerifier(encryptionSchemeId),
      deployment.ciphertextVerifier ?? config.ciphertextVerifier,
    ],
  ] as const) {
    if (!expected) continue;
    assertEqual(label, await actualPromise, expected);
  }

  if (config.bindInitialE3Program) {
    const program = new ethersLib.Contract(
      config.e3Programs[0],
      ["function interfold() view returns (address)"],
      ethers.provider,
    );
    const bound = await program.interfold();
    if (bound.toLowerCase() !== deployment.interfold.toLowerCase()) {
      throw new Error(
        `E3 Program binding: expected ${deployment.interfold}, got ${bound}`,
      );
    }
    console.log("  ok E3 Program binding");
  }

  const defaultAdmin = ethersLib.ZeroHash;
  if (!(await slashing.hasRole(defaultAdmin, config.protocolOwner))) {
    throw new Error(
      "Protocol owner does not have SlashingManager DEFAULT_ADMIN_ROLE",
    );
  }

  // Last, so that an adapter that must be replaced does not hide the results of the other checks.
  if (deployment.bondedVotes) {
    const outdated = await checkExcludedAccounts(
      ethers.provider,
      deployment.bondedVotes,
      config.bondedVotesExcludedAccounts ?? [],
      deploymentPath(config),
    );
    console.log(
      outdated ? `  -- ${outdated}` : "  ok bondedVotes.excludedAccounts",
    );
  }
  console.log("Protocol validation complete");
}
