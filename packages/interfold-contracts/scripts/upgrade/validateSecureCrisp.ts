// SPDX-License-Identifier: LGPL-3.0-only
import { ethers as ethersLib } from "ethers";
import path from "node:path";
import { pathToFileURL } from "node:url";

import {
  AVAIL_FINALIZATION_WINDOW_SECONDS,
  CRISP_MIN_VOTING_DURATION_SECONDS,
  availVectorXForChain,
} from "../dataAvailability";
import { connect } from "../protocol/cli";
import { BFV_PARAMS, ZERO } from "../protocol/constants";
import {
  deploymentPath,
  protocolDir,
  readJson,
  writeJson,
} from "../protocol/files";
import {
  currentNodeRelease,
  requiredCircuitsVersion,
} from "../protocol/nodeRelease";
import {
  assertVrfSubscription,
  readOptionalPendingRequestCount,
  requireExistingRandomnessConfig,
} from "../protocol/randomness";
import type {
  ProtocolConfigFile,
  ProtocolDeployment,
  SecureCrispUpgradePlan,
} from "../protocol/types";
import {
  encodeBfvParams,
  loadConfig,
  requireContract,
} from "../protocol/values";
import {
  PRODUCTION_BFV_CONFIG,
  activeBfvConfigForChain,
  bfvConfigsForChain,
  getBfvDecryptionSubCircuitVkHashPaths,
  getBfvPkSubCircuitVkHashPaths,
  readVkRecursiveHash,
} from "../utils";
import { proxyImplementation } from "./safeProxyUpgrade";
import { expectedCrispImageId } from "./secureCrispArtifacts";

const BFV_SCHEME_ID = ethersLib.id("fhe.rs:BFV");
const crispInterface = new ethersLib.Interface([
  "function interfold() view returns (address)",
  "function imageId() view returns (bytes32)",
  "function risc0Verifier() view returns (address)",
  "function dataAvailabilityVerifier() view returns (address)",
  "function availabilityFinalizationWindow() view returns (uint256)",
  "function MIN_VOTING_DURATION() view returns (uint256)",
  "function inputAvailabilitySigner() view returns (address)",
]);
const ciphertextInterface = new ethersLib.Interface([
  "function imageId() view returns (bytes32)",
  "function risc0Verifier() view returns (address)",
]);
const dataAvailabilityInterface = new ethersLib.Interface([
  "function bridge() view returns (address)",
  "function vectorx() view returns (address)",
]);
const availBridgeInterface = new ethersLib.Interface([
  "function vectorx() view returns (address)",
]);

function planPath(config: ProtocolConfigFile): string {
  return path.join(protocolDir, `${config.name}.secure-crisp.upgrade.json`);
}

function equalAddress(actual: string, expected: string, label: string): void {
  if (actual.toLowerCase() !== expected.toLowerCase()) {
    throw new Error(`${label} mismatch: expected ${expected}, got ${actual}`);
  }
}

function equalValue(actual: unknown, expected: unknown, label: string): void {
  if (String(actual).toLowerCase() !== String(expected).toLowerCase()) {
    throw new Error(`${label} mismatch: expected ${expected}, got ${actual}`);
  }
}

async function readContract(
  provider: any,
  target: string,
  contractInterface: ethersLib.Interface,
  functionName: string,
): Promise<any> {
  const data = contractInterface.encodeFunctionData(functionName);
  const result = await provider.call({ to: target, data });
  return contractInterface.decodeFunctionResult(functionName, result)[0];
}

export async function validateSecureCrispUpgrade(): Promise<void> {
  const { ethers } = await connect();
  const config = loadConfig();
  const deploymentFile = deploymentPath(config);
  const deployment = readJson<ProtocolDeployment>(deploymentFile);
  const plan = readJson<SecureCrispUpgradePlan>(planPath(config));
  const network = await ethers.provider.getNetwork();
  const chainId = Number(network.chainId);
  if (
    ![1, 11155111].includes(chainId) ||
    config.chainId !== chainId ||
    deployment.chainId !== chainId ||
    plan.chainId !== chainId
  ) {
    throw new Error(
      "Secure CRISP validation supports matching Ethereum mainnet or Sepolia deployments",
    );
  }
  const avail = availVectorXForChain(chainId);
  const verifierDefault = activeBfvConfigForChain(chainId);
  const verifierConfigs = bfvConfigsForChain(chainId);
  if (plan.name !== config.name) {
    throw new Error(
      `Upgrade plan name mismatch: expected ${config.name}, got ${plan.name}`,
    );
  }
  equalAddress(
    plan.protocolOwner,
    config.protocolOwner,
    "upgrade plan protocol owner",
  );
  equalValue(
    plan.cryptoConfigId,
    PRODUCTION_BFV_CONFIG.configId,
    "upgrade plan crypto config",
  );
  equalValue(plan.paramSet, 1, "upgrade plan BFV parameter set");
  equalAddress(plan.interfoldProxy, deployment.interfold, "Interfold proxy");
  equalAddress(
    plan.interfoldProxyAdmin,
    deployment.interfoldProxyAdmin,
    "Interfold ProxyAdmin",
  );
  equalAddress(
    plan.registryProxy,
    deployment.ciphernodeRegistry,
    "CiphernodeRegistry proxy",
  );
  equalAddress(
    plan.registryProxyAdmin,
    deployment.ciphernodeRegistryProxyAdmin,
    "CiphernodeRegistry ProxyAdmin",
  );
  equalAddress(
    plan.bondingProxy,
    deployment.bondingRegistryProxy,
    "BondingRegistry proxy",
  );
  equalAddress(
    plan.bondingProxyAdmin,
    deployment.bondingRegistryProxyAdmin,
    "BondingRegistry ProxyAdmin",
  );
  equalAddress(
    plan.refundManagerProxy,
    deployment.e3RefundManager,
    "E3RefundManager proxy",
  );
  equalAddress(
    plan.refundManagerProxyAdmin,
    deployment.e3RefundManagerProxyAdmin,
    "E3RefundManager ProxyAdmin",
  );
  equalAddress(
    plan.previousSlashingManager,
    deployment.slashingManager,
    "previous SlashingManager",
  );
  equalAddress(
    plan.previousRandomnessProvider,
    deployment.randomnessProvider,
    "previous randomness provider",
  );
  const resolvedRandomness = requireExistingRandomnessConfig(
    config,
    deployment,
  );
  for (const key of Object.keys(resolvedRandomness) as Array<
    keyof typeof resolvedRandomness
  >) {
    equalValue(
      plan.randomness[key],
      resolvedRandomness[key],
      `upgrade plan randomness ${key}`,
    );
  }
  equalAddress(plan.availBridge, avail.bridge, "Avail bridge");
  equalAddress(plan.vectorx, avail.vectorx, "VectorX verifier");
  equalAddress(
    plan.nodeReleaseRegistry,
    deployment.nodeReleaseRegistry,
    "NodeReleaseRegistry",
  );
  const sourceRelease = currentNodeRelease();
  equalValue(
    sourceRelease.version,
    requiredCircuitsVersion(),
    "release circuit archive version",
  );
  equalValue(
    plan.nodeRelease.version,
    sourceRelease.version,
    "node release version",
  );
  equalValue(
    plan.nodeRelease.protocolVersion,
    sourceRelease.protocolVersion,
    "node release protocol version",
  );
  equalValue(
    plan.nodeRelease.nodeGeneration,
    sourceRelease.nodeGeneration,
    "node release generation",
  );
  equalValue(
    plan.nodeRelease.releaseId,
    sourceRelease.releaseId,
    "node release ID",
  );

  const codeAddresses = [
    [plan.interfoldImplementation, "Interfold implementation"],
    [plan.registryImplementation, "CiphernodeRegistry implementation"],
    [plan.bondingImplementation, "BondingRegistry implementation"],
    [plan.refundManagerImplementation, "E3RefundManager implementation"],
    [plan.sortitionLibrary, "RegistrySortitionLib"],
    [plan.lifecycleLibrary, "InterfoldLifecycle"],
    [plan.pricingLibrary, "InterfoldPricing"],
    [plan.bondingAssetLibrary, "BondingAssetLib"],
    [plan.bondingEligibilityLibrary, "BondingEligibilityLib"],
    [plan.bondingSlashingLibrary, "BondingSlashingLib"],
    [plan.bondingRegistrationLibrary, "BondingRegistrationLib"],
    [plan.bondingOwnershipLibrary, "BondingOwnershipLib"],
    [plan.refundClaimLibrary, "RefundClaimLib"],
    [plan.slashingManager, "SlashingManager"],
    [plan.slashingEvidenceLibrary, "SlashingEvidenceLib"],
    [plan.randomnessProvider, "Chainlink VRF provider"],
    [plan.pkVerifier, "BFV PK router"],
    [plan.decryptionVerifier, "BFV decryption router"],
    [plan.ciphertextVerifier, "CRISP ciphertext verifier"],
    [plan.crispProgram, "CRISP program"],
    [plan.dataAvailabilityVerifier, "CRISP data-availability verifier"],
    [plan.availBridge, "Avail bridge"],
    [plan.vectorx, "VectorX verifier"],
    [plan.nodeReleaseRegistry, "NodeReleaseRegistry"],
    ...plan.bfvVerifierRoutes.flatMap((route) => [
      [route.pkVerifier, `${route.preset}/${route.committee} PK verifier`],
      [
        route.decryptionVerifier,
        `${route.preset}/${route.committee} decryption verifier`,
      ],
      [
        route.dkgAggregatorVerifier,
        `${route.preset}/${route.committee} DKG aggregator verifier`,
      ],
      [
        route.decryptionAggregatorVerifier,
        `${route.preset}/${route.committee} decryption aggregator verifier`,
      ],
      [
        route.verifierZkTranscriptLib,
        `${route.preset}/${route.committee} transcript library`,
      ],
      [
        route.dkgVerifierRelationsLib,
        `${route.preset}/${route.committee} DKG relations library`,
      ],
      [
        route.decryptionVerifierRelationsLib,
        `${route.preset}/${route.committee} decryption relations library`,
      ],
    ]),
  ] as Array<[string, string]>;
  await Promise.all(
    codeAddresses.map(([target, label]) =>
      requireContract(ethers.provider, target, label),
    ),
  );
  equalAddress(
    await proxyImplementation(ethers, deployment.interfold),
    plan.interfoldImplementation,
    "live Interfold implementation",
  );
  equalAddress(
    await proxyImplementation(ethers, deployment.ciphernodeRegistry),
    plan.registryImplementation,
    "live CiphernodeRegistry implementation",
  );
  equalAddress(
    await proxyImplementation(ethers, deployment.bondingRegistryProxy),
    plan.bondingImplementation,
    "live BondingRegistry implementation",
  );
  equalAddress(
    await proxyImplementation(ethers, deployment.e3RefundManager),
    plan.refundManagerImplementation,
    "live E3RefundManager implementation",
  );

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
  const refundManager = await ethers.getContractAt(
    "E3RefundManager",
    deployment.e3RefundManager,
  );
  const slashingManager = await ethers.getContractAt(
    "SlashingManager",
    plan.slashingManager,
  );
  const previousSlashingManager = await ethers.getContractAt(
    "SlashingManager",
    plan.previousSlashingManager,
  );
  const randomnessProvider = await ethers.getContractAt(
    "ChainlinkVrfRandomnessProvider",
    plan.randomnessProvider,
  );
  const releases = await ethers.getContractAt(
    "NodeReleaseRegistry",
    plan.nodeReleaseRegistry,
  );
  if (!(await interfold.requestsPaused())) {
    throw new Error("E3 requests must remain paused during validation");
  }
  equalAddress(
    await interfold.owner(),
    config.protocolOwner,
    "Interfold owner",
  );
  equalValue(await interfold.activeE3Count(), 0n, "active E3 count");
  equalValue(
    await registry.unreleasedCommitteeCount(),
    0n,
    "unreleased committee count",
  );
  equalValue(
    await bonding.unresolvedCommitteeCount(),
    0n,
    "unresolved committee count",
  );
  equalValue(
    await registry.numCiphernodes(),
    BigInt(plan.registeredOperatorCount),
    "registered registry operators",
  );
  equalValue(
    await bonding.numRegisteredOperators(),
    BigInt(plan.registeredOperatorCount),
    "registered bonding operators",
  );
  equalValue(
    await bonding.numActiveOperators(),
    BigInt(plan.activeOperatorCount),
    "active bonding operators",
  );
  equalValue(await registry.root(), BigInt(plan.registryRoot), "registry root");
  for (const [label, actual, expected] of [
    [
      "Interfold registry",
      await interfold.ciphernodeRegistry(),
      plan.registryProxy,
    ],
    [
      "Interfold bonding registry",
      await interfold.bondingRegistry(),
      plan.bondingProxy,
    ],
    [
      "Interfold refund manager",
      await interfold.e3RefundManager(),
      plan.refundManagerProxy,
    ],
    [
      "Interfold slashing manager",
      await interfold.slashingManager(),
      plan.slashingManager,
    ],
    ["registry Interfold", await registry.interfold(), plan.interfoldProxy],
    [
      "registry bonding registry",
      await registry.bondingRegistry(),
      plan.bondingProxy,
    ],
    [
      "registry slashing manager",
      await registry.slashingManager(),
      plan.slashingManager,
    ],
    [
      "registry randomness provider",
      await registry.randomnessProvider(),
      plan.randomnessProvider,
    ],
    ["bonding registry", await bonding.registry(), plan.registryProxy],
    [
      "bonding slashing manager",
      await bonding.slashingManager(),
      plan.slashingManager,
    ],
    [
      "refund manager Interfold",
      await refundManager.interfold(),
      plan.interfoldProxy,
    ],
    [
      "refund manager bonding registry",
      await refundManager.bondingRegistry(),
      plan.bondingProxy,
    ],
    [
      "slashing manager Interfold",
      await slashingManager.interfold(),
      plan.interfoldProxy,
    ],
    [
      "slashing manager registry",
      await slashingManager.ciphernodeRegistry(),
      plan.registryProxy,
    ],
    [
      "slashing manager bonding registry",
      await slashingManager.bondingRegistry(),
      plan.bondingProxy,
    ],
    [
      "slashing manager refund manager",
      await slashingManager.e3RefundManager(),
      plan.refundManagerProxy,
    ],
  ] as const) {
    equalAddress(String(actual), expected, label);
  }
  for (const [label, owner] of [
    ["BondingRegistry owner", await bonding.owner()],
    ["E3RefundManager owner", await refundManager.owner()],
    ["SlashingManager admin", await slashingManager.defaultAdmin()],
  ] as const) {
    equalAddress(String(owner), config.protocolOwner, label);
  }
  equalValue(
    await slashingManager.activeE3Assignments(),
    0n,
    "replacement manager active E3 assignments",
  );
  equalValue(
    await slashingManager.activeBanCount(),
    0n,
    "replacement manager active bans",
  );
  equalValue(
    await previousSlashingManager.activeE3Assignments(),
    0n,
    "previous manager active E3 assignments",
  );
  equalValue(
    await previousSlashingManager.activeBanCount(),
    0n,
    "previous manager active bans",
  );
  equalValue(
    await bonding.isAuthorizedSlashingManager(plan.slashingManager),
    true,
    "replacement manager authorization",
  );
  equalValue(
    await bonding.isAuthorizedSlashingManager(plan.previousSlashingManager),
    false,
    "previous manager authorization",
  );
  const governanceRole = await slashingManager.GOVERNANCE_ROLE();
  equalValue(
    await slashingManager.hasRole(governanceRole, config.protocolOwner),
    true,
    "SlashingManager governance role",
  );
  if (config.slasher.toLowerCase() !== ZERO.toLowerCase()) {
    const slasherRole = await slashingManager.SLASHER_ROLE();
    equalValue(
      await slashingManager.hasRole(slasherRole, config.slasher),
      true,
      "configured slasher role",
    );
  }
  const slashPolicyFields = [
    "ticketPenalty",
    "ciphernodeBondPenalty",
    "requiresProof",
    "proofVerifier",
    "banNode",
    "appealWindow",
    "enabled",
    "affectsCommittee",
    "failureReason",
  ] as const;
  for (const reason of plan.migratedSlashPolicyReasons) {
    const [previousPolicy, migratedPolicy] = await Promise.all([
      previousSlashingManager.getSlashPolicy(reason),
      slashingManager.getSlashPolicy(reason),
    ]);
    for (const field of slashPolicyFields) {
      equalValue(
        migratedPolicy[field],
        previousPolicy[field],
        `slash policy ${reason} ${field}`,
      );
    }
  }
  equalAddress(
    await randomnessProvider.requester(),
    plan.registryProxy,
    "randomness provider requester",
  );
  equalAddress(
    await randomnessProvider.owner(),
    config.protocolOwner,
    "randomness provider owner",
  );
  for (const [label, actual, expected] of [
    [
      "subscription ID",
      await randomnessProvider.subscriptionId(),
      plan.randomness.subscriptionId,
    ],
    ["key hash", await randomnessProvider.keyHash(), plan.randomness.keyHash],
    [
      "request confirmations",
      await randomnessProvider.requestConfirmations(),
      plan.randomness.requestConfirmations,
    ],
    [
      "callback gas limit",
      await randomnessProvider.callbackGasLimit(),
      plan.randomness.callbackGasLimit,
    ],
    [
      "native payment",
      await randomnessProvider.nativePayment(),
      plan.randomness.nativePayment,
    ],
    [
      "minimum subscription balance",
      await randomnessProvider.minimumSubscriptionBalance(),
      plan.randomness.minimumSubscriptionBalance,
    ],
    [
      "randomness request timeout",
      await registry.randomnessRequestTimeout(),
      plan.randomness.requestTimeout,
    ],
  ] as const) {
    equalValue(actual, expected, `randomness ${label}`);
  }
  equalValue(
    await randomnessProvider.pendingRequestCount(),
    0n,
    "replacement randomness pending requests",
  );
  const previousPendingRequests = await readOptionalPendingRequestCount(
    ethers.provider,
    plan.previousRandomnessProvider,
  );
  if (previousPendingRequests !== undefined) {
    equalValue(
      previousPendingRequests,
      0n,
      "previous randomness pending requests",
    );
  }
  const effectiveConfig = { ...config, randomness: plan.randomness };
  await assertVrfSubscription(ethers, effectiveConfig, plan.randomnessProvider);
  await assertVrfSubscription(
    ethers,
    effectiveConfig,
    plan.previousRandomnessProvider,
  );
  equalAddress(
    await interfold.nodeReleaseRegistry(),
    plan.nodeReleaseRegistry,
    "Interfold node release registry",
  );
  equalAddress(
    await releases.owner(),
    config.protocolOwner,
    "NodeReleaseRegistry owner",
  );
  equalAddress(
    await releases.bondingRegistry(),
    config.bondingRegistryProxy,
    "NodeReleaseRegistry BondingRegistry",
  );
  equalAddress(
    await releases.ciphernodeRegistry(),
    deployment.ciphernodeRegistry,
    "NodeReleaseRegistry CiphernodeRegistry",
  );
  equalValue(
    await releases.requiredProtocolVersion(),
    plan.nodeRelease.protocolVersion,
    "required protocol version",
  );
  equalValue(
    await releases.requiredNodeGeneration(),
    plan.nodeRelease.nodeGeneration,
    "required node generation",
  );
  equalValue(
    await interfold.activeCryptoConfigId(),
    PRODUCTION_BFV_CONFIG.configId,
    "active crypto config",
  );
  equalValue(
    await interfold.paramSetRegistry(1),
    encodeBfvParams(BFV_PARAMS.secure8192),
    "secure BFV parameter set",
  );
  for (const threshold of config.interfold.committeeThresholds) {
    const size = BigInt(threshold.size);
    const actual = await Promise.all([
      interfold.committeeThresholds(size, 0n),
      interfold.committeeThresholds(size, 1n),
    ]);
    equalValue(
      actual[0],
      BigInt(threshold.quorum),
      `committee ${threshold.size} quorum`,
    );
    equalValue(
      actual[1],
      BigInt(threshold.total),
      `committee ${threshold.size} total`,
    );
  }
  equalAddress(
    await interfold.pkVerifiers(BFV_SCHEME_ID),
    plan.pkVerifier,
    "BFV PK verifier",
  );
  equalAddress(
    await interfold.decryptionVerifiers(BFV_SCHEME_ID),
    plan.decryptionVerifier,
    "BFV decryption verifier",
  );
  equalAddress(
    await interfold.getCiphertextVerifier(BFV_SCHEME_ID),
    plan.ciphertextVerifier,
    "BFV ciphertext verifier",
  );
  if (!(await interfold.e3Programs(plan.crispProgram))) {
    throw new Error("CRISP program is not registered");
  }
  for (const program of plan.retiredE3Programs) {
    if (program.toLowerCase() === plan.crispProgram.toLowerCase()) {
      throw new Error("Upgrade plan cannot retire the active CRISP program");
    }
    if (await interfold.e3Programs(program)) {
      throw new Error(
        `Retired E3 program still accepts new requests: ${program}`,
      );
    }
  }
  const initialE3Program = deployment.initialE3Program;
  if (initialE3Program.toLowerCase() !== plan.crispProgram.toLowerCase()) {
    if (await interfold.e3Programs(initialE3Program)) {
      throw new Error("Initial E3 program still accepts new requests");
    }
  }
  equalAddress(
    String(
      await readContract(
        ethers.provider,
        plan.crispProgram,
        crispInterface,
        "interfold",
      ),
    ),
    deployment.interfold,
    "CRISP Interfold binding",
  );
  equalAddress(
    String(
      await readContract(
        ethers.provider,
        plan.crispProgram,
        crispInterface,
        "dataAvailabilityVerifier",
      ),
    ),
    plan.dataAvailabilityVerifier,
    "CRISP data-availability verifier",
  );
  equalValue(
    await readContract(
      ethers.provider,
      plan.crispProgram,
      crispInterface,
      "availabilityFinalizationWindow",
    ),
    AVAIL_FINALIZATION_WINDOW_SECONDS,
    "CRISP availability finalization window",
  );
  equalValue(
    await readContract(
      ethers.provider,
      plan.crispProgram,
      crispInterface,
      "MIN_VOTING_DURATION",
    ),
    CRISP_MIN_VOTING_DURATION_SECONDS,
    "CRISP minimum voting duration",
  );
  equalAddress(
    String(
      await readContract(
        ethers.provider,
        plan.crispProgram,
        crispInterface,
        "inputAvailabilitySigner",
      ),
    ),
    plan.inputAvailabilitySigner,
    "CRISP input availability signer",
  );
  equalAddress(
    String(
      await readContract(
        ethers.provider,
        plan.dataAvailabilityVerifier,
        dataAvailabilityInterface,
        "bridge",
      ),
    ),
    plan.availBridge,
    "adapter Avail bridge",
  );
  equalAddress(
    String(
      await readContract(
        ethers.provider,
        plan.dataAvailabilityVerifier,
        dataAvailabilityInterface,
        "vectorx",
      ),
    ),
    plan.vectorx,
    "adapter VectorX verifier",
  );
  equalAddress(
    String(
      await readContract(
        ethers.provider,
        plan.availBridge,
        availBridgeInterface,
        "vectorx",
      ),
    ),
    plan.vectorx,
    "live bridge VectorX verifier",
  );

  const crispImage = await readContract(
    ethers.provider,
    plan.crispProgram,
    crispInterface,
    "imageId",
  );
  const ciphertextImage = await readContract(
    ethers.provider,
    plan.ciphertextVerifier,
    ciphertextInterface,
    "imageId",
  );
  equalValue(ciphertextImage, crispImage, "CRISP image ID");
  equalValue(crispImage, expectedCrispImageId(), "release CRISP image ID");
  const crispRisc0 = String(
    await readContract(
      ethers.provider,
      plan.crispProgram,
      crispInterface,
      "risc0Verifier",
    ),
  );
  const ciphertextRisc0 = String(
    await readContract(
      ethers.provider,
      plan.ciphertextVerifier,
      ciphertextInterface,
      "risc0Verifier",
    ),
  );
  equalAddress(ciphertextRisc0, crispRisc0, "CRISP RISC Zero verifier");
  await requireContract(
    ethers.provider,
    crispRisc0,
    "CRISP RISC Zero verifier",
  );

  if (plan.bfvVerifierRoutes.length !== verifierConfigs.length) {
    throw new Error(
      `Expected ${verifierConfigs.length} BFV routes, got ${plan.bfvVerifierRoutes.length}`,
    );
  }
  const pkRouter = await ethers.getContractAt(
    "BfvPkVerifierRouter",
    plan.pkVerifier,
  );
  const decryptionRouter = await ethers.getContractAt(
    "BfvDecryptionVerifierRouter",
    plan.decryptionVerifier,
  );
  equalValue(await pkRouter.h(), verifierDefault.h, "PK router default h");
  equalValue(
    await decryptionRouter.threshold(),
    verifierDefault.t,
    "decryption router default threshold",
  );
  const expectedRouteCount = BigInt(verifierConfigs.length);
  equalValue(await pkRouter.routeCount(), expectedRouteCount, "PK route count");
  equalValue(
    await decryptionRouter.routeCount(),
    expectedRouteCount,
    "decryption route count",
  );

  for (let index = 0; index < verifierConfigs.length; index += 1) {
    const expected = verifierConfigs[index];
    const recorded = plan.bfvVerifierRoutes[index];
    if (
      recorded.preset !== expected.preset ||
      recorded.committee !== expected.committee ||
      recorded.paramSet !== expected.paramSet ||
      recorded.committeeSize !== expected.committeeSize
    ) {
      throw new Error(
        `Recorded BFV route ${index} does not match the release matrix`,
      );
    }

    const pkRoute = await pkRouter.routeAt(index);
    const decryptionRoute = await decryptionRouter.routeAt(index);
    equalAddress(pkRoute[0], recorded.pkVerifier, `PK route ${index}`);
    equalValue(
      pkRoute[1],
      3 * expected.h + 6,
      `PK route ${index} public input count`,
    );
    equalAddress(
      decryptionRoute[0],
      recorded.decryptionVerifier,
      `decryption route ${index}`,
    );
    equalValue(
      decryptionRoute[1],
      111 + 3 * expected.t,
      `decryption route ${index} public input count`,
    );

    const pkVerifier = await ethers.getContractAt(
      "BfvPkVerifier",
      recorded.pkVerifier,
    );
    const decryptionVerifier = await ethers.getContractAt(
      "BfvDecryptionVerifier",
      recorded.decryptionVerifier,
    );
    equalValue(await pkVerifier.h(), expected.h, `PK route ${index} h`);
    equalValue(
      await decryptionVerifier.threshold(),
      expected.t,
      `decryption route ${index} threshold`,
    );
    equalAddress(
      await pkVerifier.circuitVerifier(),
      recorded.dkgAggregatorVerifier,
      `PK route ${index} aggregator`,
    );
    equalAddress(
      await decryptionVerifier.circuitVerifier(),
      recorded.decryptionAggregatorVerifier,
      `decryption route ${index} aggregator`,
    );
    equalAddress(
      await decryptionVerifier.ciphernodeRegistry(),
      plan.registryProxy,
      `decryption route ${index} registry`,
    );
    const pkPaths = getBfvPkSubCircuitVkHashPaths(expected);
    const decryptionPaths = getBfvDecryptionSubCircuitVkHashPaths(expected);
    equalValue(
      pkRoute[2],
      readVkRecursiveHash(pkPaths.nodesFold, expected),
      `PK route ${index} nodes-fold VK`,
    );
    equalValue(
      pkRoute[3],
      readVkRecursiveHash(pkPaths.c5, expected),
      `PK route ${index} C5 VK`,
    );
    equalValue(
      decryptionRoute[2],
      readVkRecursiveHash(decryptionPaths.c6Fold, expected),
      `decryption route ${index} C6-fold VK`,
    );
    equalValue(
      decryptionRoute[3],
      readVkRecursiveHash(decryptionPaths.c7, expected),
      `decryption route ${index} C7 VK`,
    );
  }

  deployment.interfoldImplementation = plan.interfoldImplementation;
  deployment.interfoldLifecycle = plan.lifecycleLibrary;
  deployment.interfoldPricing = plan.pricingLibrary;
  deployment.ciphernodeRegistryImplementation = plan.registryImplementation;
  deployment.registrySortitionLib = plan.sortitionLibrary;
  deployment.bondingRegistryImplementation = plan.bondingImplementation;
  deployment.bondingAssetLib = plan.bondingAssetLibrary;
  deployment.bondingEligibilityLib = plan.bondingEligibilityLibrary;
  deployment.bondingSlashingLib = plan.bondingSlashingLibrary;
  deployment.bondingRegistrationLib = plan.bondingRegistrationLibrary;
  deployment.bondingOwnershipLib = plan.bondingOwnershipLibrary;
  deployment.e3RefundManagerImplementation = plan.refundManagerImplementation;
  deployment.refundClaimLib = plan.refundClaimLibrary;
  deployment.slashingManager = plan.slashingManager;
  deployment.slashingEvidenceLib = plan.slashingEvidenceLibrary;
  deployment.randomnessProvider = plan.randomnessProvider;
  deployment.randomness = { ...plan.randomness };
  deployment.randomnessProviderOwnershipAcceptanceRequired = false;
  deployment.pkVerifier = plan.pkVerifier;
  deployment.decryptionVerifier = plan.decryptionVerifier;
  deployment.ciphertextVerifier = plan.ciphertextVerifier;
  deployment.crispProgram = plan.crispProgram;
  deployment.dataAvailabilityVerifier = plan.dataAvailabilityVerifier;
  deployment.bfvVerifierRoutes = plan.bfvVerifierRoutes;
  const first = plan.bfvVerifierRoutes[0];
  deployment.dkgAggregatorVerifier = first.dkgAggregatorVerifier;
  deployment.decryptionAggregatorVerifier = first.decryptionAggregatorVerifier;
  deployment.verifierZkTranscriptLib = first.verifierZkTranscriptLib;
  deployment.dkgVerifierRelationsLib = first.dkgVerifierRelationsLib;
  deployment.decryptionVerifierRelationsLib =
    first.decryptionVerifierRelationsLib;
  writeJson(deploymentFile, deployment);

  console.log(`
Secure CRISP activation validated
  crypto config:       ${PRODUCTION_BFV_CONFIG.configId}
  operators preserved: ${plan.activeOperatorCount}/${plan.registeredOperatorCount}
  registry root:       ${plan.registryRoot}
  slashing manager:    ${plan.slashingManager}
  VRF provider:        ${plan.randomnessProvider}
  VRF subscription:    ${plan.randomness.subscriptionId} (reused)
  secure BFV routes:   ${plan.bfvVerifierRoutes.length}
  CRISP program:       ${plan.crispProgram}
  DA verifier:         ${plan.dataAvailabilityVerifier}
  node protocol:       ${plan.nodeRelease.protocolVersion}
  requests paused:     true

Restart matching ciphernodes and validate them before resuming requests.
`);
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
  validateSecureCrispUpgrade().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}
