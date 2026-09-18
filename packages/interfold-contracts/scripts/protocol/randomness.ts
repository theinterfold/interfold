// SPDX-License-Identifier: LGPL-3.0-only
import { ethers as ethersLib } from "ethers";

import { assertSupportedVrfChain, assertVrfRequestTimeout } from "./chains";
import { safeTx } from "./safe";
import type {
  ProtocolConfigFile,
  ProtocolContracts,
  ProtocolDeployment,
  ProtocolInterfaces,
  RandomnessConfig,
  SafeTransaction,
  VrfSortitionUpgradePlan,
} from "./types";
import { deployedAddress } from "./values";

export const vrfCoordinatorInterface = new ethersLib.Interface([
  "function addConsumer(uint256 subId,address consumer)",
  "function getSubscription(uint256 subId) view returns (uint96 balance,uint96 nativeBalance,uint64 reqCount,address owner,address[] consumers)",
  "function s_config() view returns (uint16 minimumRequestConfirmations,uint32 maxGasLimit,bool reentrancyLock,uint32 stalenessSeconds,uint32 gasAfterPaymentCalculation,uint32 fulfillmentFlatFeeNativePPM,uint32 fulfillmentFlatFeeLinkDiscountPPM,uint8 nativePremiumPercentage,uint8 linkPremiumPercentage)",
  "function s_provingKeys(bytes32 keyHash) view returns (bool exists,uint64 maxGas)",
]);

export const vrfProviderInterface = new ethersLib.Interface([
  "function acceptOwnership()",
]);
const pendingRequestInterface = new ethersLib.Interface([
  "function pendingRequestCount() view returns (uint256)",
]);

async function readPendingRequestCount(
  provider: ethersLib.Provider,
  target: string,
): Promise<bigint | undefined> {
  const result = await provider.call({
    to: target,
    data: pendingRequestInterface.encodeFunctionData("pendingRequestCount"),
  });
  if (result === "0x") return undefined;
  return pendingRequestInterface.decodeFunctionResult(
    "pendingRequestCount",
    result,
  )[0] as bigint;
}

function isUnavailablePendingRequestCount(error: unknown): boolean {
  if (typeof error !== "object" || error === null) return false;
  const rpcError = error as {
    code?: string | number;
    data?: unknown;
    value?: unknown;
  };
  if (
    rpcError.code === 3 &&
    (rpcError.data === undefined || rpcError.data === "0x")
  ) {
    return true;
  }
  return (
    (rpcError.data === "0x" &&
      (rpcError.code === undefined ||
        rpcError.code === "CALL_EXCEPTION" ||
        rpcError.code === 3)) ||
    (rpcError.code === "BAD_DATA" && rpcError.value === "0x")
  );
}

/** Read the reservation count when the deployed provider exposes it. */
export async function readOptionalPendingRequestCount(
  provider: ethersLib.Provider,
  target: string,
): Promise<bigint | undefined> {
  try {
    const pending = await readPendingRequestCount(provider, target);
    if (pending !== undefined) return pending;
  } catch (readError) {
    const code = await provider.getCode(target);
    if (code === "0x") throw readError;
    try {
      return await readPendingRequestCount(provider, target);
    } catch (retryError) {
      if (isUnavailablePendingRequestCount(retryError)) return undefined;
      throw retryError;
    }
  }

  const code = await provider.getCode(target);
  if (code === "0x") {
    throw new Error(`randomness provider ${target} has no deployed code`);
  }
  return readPendingRequestCount(provider, target);
}

export function requireCiphernodeRestartAcknowledgement(
  acknowledged: boolean,
): void {
  if (!acknowledged) {
    throw new Error(
      "Refusing to prepare the resume transaction. Restart every ciphernode on the matching release, then pass --ciphernodes-restarted.",
    );
  }
}

export function requireRandomnessConfig(
  config: ProtocolConfigFile,
): RandomnessConfig {
  assertSupportedVrfChain(config.chainId);
  if (!config.randomness) {
    throw new Error("randomness configuration is required");
  }
  if (BigInt(config.randomness.subscriptionId) === 0n) {
    throw new Error("randomness.subscriptionId must not be zero");
  }
  return config.randomness;
}

function assertRandomnessValue(
  label: string,
  actual: string | number | boolean,
  expected: string | number | boolean,
): void {
  if (String(actual).toLowerCase() !== String(expected).toLowerCase()) {
    throw new Error(`${label}: expected ${expected}, got ${actual}`);
  }
}

function assertRandomnessConfigMatches(
  label: string,
  actual: RandomnessConfig,
  expected: RandomnessConfig,
  allowZeroSubscriptionPlaceholder = false,
): void {
  for (const [field, actualValue, expectedValue] of [
    ["coordinator", actual.coordinator, expected.coordinator],
    ["subscriptionId", actual.subscriptionId, expected.subscriptionId],
    ["keyHash", actual.keyHash, expected.keyHash],
    [
      "requestConfirmations",
      actual.requestConfirmations,
      expected.requestConfirmations,
    ],
    ["callbackGasLimit", actual.callbackGasLimit, expected.callbackGasLimit],
    ["nativePayment", actual.nativePayment, expected.nativePayment],
    [
      "minimumSubscriptionBalance",
      actual.minimumSubscriptionBalance,
      expected.minimumSubscriptionBalance,
    ],
    ["requestTimeout", actual.requestTimeout, expected.requestTimeout],
  ] as const) {
    if (
      field === "subscriptionId" &&
      allowZeroSubscriptionPlaceholder &&
      BigInt(String(actualValue)) === 0n
    ) {
      continue;
    }
    assertRandomnessValue(`${label}.${field}`, actualValue, expectedValue);
  }
}

export function requirePlannedRandomnessConfig(
  config: ProtocolConfigFile,
  plan: VrfSortitionUpgradePlan,
): RandomnessConfig {
  if (!plan.randomness) {
    throw new Error("VRF upgrade plan has no randomness configuration");
  }
  if (!config.randomness) {
    throw new Error("randomness configuration is required");
  }
  assertRandomnessConfigMatches(
    "config.randomness",
    config.randomness,
    plan.randomness,
    true,
  );
  assertRandomnessValue(
    "config.interfold.pricing.randomnessFlatFee",
    config.interfold.pricing.randomnessFlatFee,
    plan.randomnessFlatFee,
  );
  assertSupportedVrfChain(config.chainId);
  assertVrfRequestTimeout(
    config.chainId,
    plan.randomness.requestConfirmations,
    BigInt(plan.randomness.requestTimeout),
  );
  return plan.randomness;
}

/**
 * Resolve the funded subscription for a replacement provider.
 *
 * A committed production config can keep subscription ID `0` as a deployment
 * placeholder. In that case, use the validated subscription recorded by the
 * existing deployment. All other settings must remain equal.
 */
export function requireExistingRandomnessConfig(
  config: ProtocolConfigFile,
  deployment: ProtocolDeployment,
): RandomnessConfig {
  if (!config.randomness) {
    throw new Error("randomness configuration is required");
  }
  if (!deployment.randomness) {
    throw new Error("deployment randomness configuration is required");
  }
  assertRandomnessConfigMatches(
    "config.randomness",
    config.randomness,
    deployment.randomness,
    true,
  );
  const configuredSubscription = BigInt(config.randomness.subscriptionId);
  const resolved =
    configuredSubscription === 0n ? deployment.randomness : config.randomness;
  if (BigInt(resolved.subscriptionId) === 0n) {
    throw new Error("funded randomness subscription ID is required");
  }
  return { ...resolved };
}

export function assertValidatedVrfDeploymentMatchesPlan(
  deployment: ProtocolDeployment,
  plan: VrfSortitionUpgradePlan,
): void {
  for (const [label, actual, expected] of [
    [
      "deployment registry implementation",
      deployment.ciphernodeRegistryImplementation,
      plan.registryImplementation,
    ],
    [
      "deployment sortition library",
      deployment.registrySortitionLib,
      plan.sortitionLibrary,
    ],
    [
      "deployment Interfold implementation",
      deployment.interfoldImplementation,
      plan.interfoldImplementation,
    ],
    [
      "deployment lifecycle library",
      deployment.interfoldLifecycle,
      plan.lifecycleLibrary,
    ],
    [
      "deployment pricing library",
      deployment.interfoldPricing,
      plan.pricingLibrary,
    ],
    [
      "deployment randomness provider",
      deployment.randomnessProvider,
      plan.randomnessProvider,
    ],
    [
      "deployment BondingRegistry implementation",
      deployment.bondingRegistryImplementation,
      plan.bondingImplementation,
    ],
    [
      "deployment node release registry",
      deployment.nodeReleaseRegistry,
      plan.nodeReleaseRegistry,
    ],
  ] as const) {
    assertPlanValue(label, actual, expected);
  }
  if (!deployment.randomness) {
    throw new Error(
      "Validated deployment has no recorded randomness configuration",
    );
  }
  assertRandomnessConfigMatches(
    "deployment.randomness",
    deployment.randomness,
    plan.randomness,
  );
}

export async function assertVrfSubscription(
  ethers: any,
  config: ProtocolConfigFile,
  expectedConsumer?: string,
): Promise<void> {
  const randomness = requireRandomnessConfig(config);
  assertVrfRequestTimeout(
    config.chainId,
    randomness.requestConfirmations,
    BigInt(randomness.requestTimeout),
  );
  const coordinator = new ethersLib.Contract(
    randomness.coordinator,
    vrfCoordinatorInterface,
    ethers.provider,
  );
  const coordinatorConfig = await coordinator.s_config();
  if (
    BigInt(randomness.requestConfirmations) <
    BigInt(coordinatorConfig.minimumRequestConfirmations)
  ) {
    throw new Error(
      `randomness.requestConfirmations is below the coordinator minimum of ${coordinatorConfig.minimumRequestConfirmations}`,
    );
  }
  if (
    BigInt(randomness.callbackGasLimit) > BigInt(coordinatorConfig.maxGasLimit)
  ) {
    throw new Error(
      `randomness.callbackGasLimit exceeds the coordinator maximum of ${coordinatorConfig.maxGasLimit}`,
    );
  }
  const provingKey = await coordinator.s_provingKeys(randomness.keyHash);
  if (!provingKey.exists) {
    throw new Error(
      `randomness.keyHash is not registered with coordinator ${randomness.coordinator}`,
    );
  }
  const subscription = await coordinator.getSubscription(
    BigInt(randomness.subscriptionId),
  );
  if (
    String(subscription.owner).toLowerCase() !==
    config.protocolOwner.toLowerCase()
  ) {
    throw new Error(
      `VRF subscription owner mismatch: expected ${config.protocolOwner}, got ${subscription.owner}`,
    );
  }
  const balance = randomness.nativePayment
    ? subscription.nativeBalance
    : subscription.balance;
  const minimumBalance = BigInt(randomness.minimumSubscriptionBalance);
  if (balance < minimumBalance) {
    throw new Error(
      `VRF subscription ${randomness.subscriptionId} ${
        randomness.nativePayment ? "native" : "LINK"
      } balance ${balance} is below the configured minimum ${minimumBalance}`,
    );
  }
  if (
    expectedConsumer &&
    !subscription.consumers.some(
      (consumer: string) =>
        consumer.toLowerCase() === expectedConsumer.toLowerCase(),
    )
  ) {
    throw new Error(
      `VRF subscription does not include consumer ${expectedConsumer}`,
    );
  }
}

function assertPlanValue(
  label: string,
  actual: string | number,
  expected: string | number,
): void {
  if (String(actual).toLowerCase() !== String(expected).toLowerCase()) {
    throw new Error(`${label}: expected ${expected}, got ${actual}`);
  }
}

export function assertVrfUpgradePlanMatchesDeployment(
  config: ProtocolConfigFile,
  deployment: ProtocolDeployment,
  plan: VrfSortitionUpgradePlan,
  connectedChainId: bigint,
): void {
  assertPlanValue(
    "connected chain",
    connectedChainId.toString(),
    config.chainId,
  );
  assertPlanValue("deployment chain", deployment.chainId, config.chainId);
  assertPlanValue("plan name", plan.name, config.name);
  assertPlanValue(
    "plan protocol owner",
    plan.protocolOwner,
    config.protocolOwner,
  );
  assertPlanValue(
    "deployment protocol owner",
    deployment.protocolOwner,
    config.protocolOwner,
  );
  assertPlanValue(
    "registry proxy",
    plan.registryProxy,
    deployment.ciphernodeRegistry,
  );
  assertPlanValue(
    "registry ProxyAdmin",
    plan.registryProxyAdmin,
    deployment.ciphernodeRegistryProxyAdmin,
  );
  assertPlanValue("Interfold proxy", plan.interfoldProxy, deployment.interfold);
  assertPlanValue(
    "Interfold ProxyAdmin",
    plan.interfoldProxyAdmin,
    deployment.interfoldProxyAdmin,
  );
  assertPlanValue(
    "BondingRegistry proxy",
    plan.bondingProxy,
    config.bondingRegistryProxy,
  );
  assertPlanValue(
    "BondingRegistry ProxyAdmin",
    plan.bondingProxyAdmin,
    config.bondingRegistryProxyAdmin,
  );
}

export async function deployRandomnessProvider(
  ethers: any,
  operator: any,
  config: ProtocolConfigFile,
  registry: string,
): Promise<{
  randomnessProvider: string;
  randomnessProviderOwnershipAcceptanceRequired: boolean;
}> {
  const randomness = requireRandomnessConfig(config);
  const factory = await ethers.getContractFactory(
    "ChainlinkVrfRandomnessProvider",
  );
  const provider = await factory.deploy(
    registry,
    randomness.coordinator,
    BigInt(randomness.subscriptionId),
    randomness.keyHash,
    randomness.requestConfirmations,
    randomness.callbackGasLimit,
    randomness.nativePayment,
    BigInt(randomness.minimumSubscriptionBalance),
    config.protocolOwner,
  );
  await provider.waitForDeployment();
  return {
    randomnessProvider: await deployedAddress(provider),
    randomnessProviderOwnershipAcceptanceRequired:
      (await operator.getAddress()).toLowerCase() !==
      config.protocolOwner.toLowerCase(),
  };
}

export function appendRandomnessTxs(
  txs: SafeTransaction[],
  config: ProtocolConfigFile,
  contracts: ProtocolContracts,
  interfaces: ProtocolInterfaces,
): void {
  txs.push(
    ...buildRandomnessTransactions(
      config,
      contracts.randomnessProvider,
      contracts.ciphernodeRegistry,
      interfaces.registry,
      Boolean(contracts.randomnessProviderOwnershipAcceptanceRequired),
    ),
  );
}

export function buildRandomnessTransactions(
  config: ProtocolConfigFile,
  randomnessProvider: string,
  registry: string,
  registryInterface: ProtocolInterfaces["registry"],
  acceptProviderOwnership: boolean,
): SafeTransaction[] {
  const randomness = requireRandomnessConfig(config);
  const txs: SafeTransaction[] = [];
  if (acceptProviderOwnership) {
    txs.push(
      safeTx(
        randomnessProvider,
        vrfProviderInterface.encodeFunctionData("acceptOwnership"),
      ),
    );
  }
  txs.push(
    safeTx(
      randomness.coordinator,
      vrfCoordinatorInterface.encodeFunctionData("addConsumer", [
        BigInt(randomness.subscriptionId),
        randomnessProvider,
      ]),
    ),
    safeTx(
      registry,
      registryInterface.encodeFunctionData("setRandomnessRequestTimeout", [
        BigInt(randomness.requestTimeout),
      ]),
    ),
    safeTx(
      registry,
      registryInterface.encodeFunctionData("setRandomnessProvider", [
        randomnessProvider,
      ]),
    ),
  );
  return txs;
}
