// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
//
// Bond-owner identity gate rollout. Each action writes a governance batch; it sends no governance
// transaction itself.
//
//   prepare   Deploys ZKPassportIdentityVerifier, OwnerIdentityRegistry, and a BondingRegistry
//             implementation. The batch upgrades BondingRegistry, publishes the registry with
//             `required = false`, and refreshes every registered operator.
//   enforce   The batch sets `required = true` and refreshes every registered operator.
//   relax     The batch sets `required = false` and refreshes every registered operator (rollback).
//   validate  Reads back the deployment against the plan, the policy, and the owner capacity.
//
// Every identity policy change resets counted owner capacity, so each batch refreshes all
// registered operators in the same transaction. Without that, requests fail until a refresh.
import { ethers as ethersLib } from "ethers";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { assertRefreshedOwnerCapacity } from "../../tasks/committeeCapacity";
import { BondingRegistry__factory as BondingRegistryFactory } from "../../types";
import { assertAragonGovernancePreconditions } from "../protocol/actions";
import { arg, connect, hasFlag, networkName } from "../protocol/cli";
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
  aragonAdminSafeBatch,
  aragonAdminSafeTransactions,
  governanceBatch,
  proposeSafeBatch,
  safeTx,
} from "../protocol/safe";
import type {
  IdentityGateConfig,
  ProtocolConfigFile,
  ProtocolDeployment,
  SafeTransaction,
} from "../protocol/types";
import {
  address,
  deployedAddress,
  loadConfig,
  requireContract,
} from "../protocol/values";
import { verifyRecordedDeployments } from "../sourceVerification";
import {
  deployUpgradeImplementation,
  proxyImplementation,
} from "./safeProxyUpgrade";
import {
  addedOperators,
  registryDeployBlock,
  requiredActiveOperators,
} from "./v19Cutover";

const bondingInterface = BondingRegistryFactory.createInterface();
const ZERO_HASH = ethersLib.ZeroHash;
/** Operators per `refreshOperatorStatuses` call, as in the v0.19 refresh. */
export const REFRESH_BATCH = 20;
/**
 * The batch refreshes every operator in one governance transaction, so its gas grows with the
 * operator count. Above this count, pause requests and refresh in stages instead.
 */
export const MAX_BATCH_OPERATORS = 200;
/** `BondOwnerCapacityLib.IDENTITY_CAPACITY_WINDOW`. Windows start at multiples of it. */
export const CAPACITY_WINDOW = 30n * 86_400n;
/** Time to execute an enforce batch when `--execute-by` is not given: the Safe signs it meanwhile. */
export const EXECUTION_MARGIN = 7n * 86_400n;
const IDENTITY_TAG = "interfold.identity.zkpassport.v1";

/** The last second of the capacity window that contains `timestamp` (`_windowEnd`). */
export function capacityWindowEnd(timestamp: bigint): bigint {
  return (timestamp / CAPACITY_WINDOW + 1n) * CAPACITY_WINDOW - 1n;
}

/**
 * The end of the capacity window that contains the latest execution of an enforce batch. An owner
 * whose credential lasts to it counts at any execution until then, in this window or the next.
 */
export function enforceDeadline(now: bigint, executeBy?: string): bigint {
  if (executeBy === undefined) return capacityWindowEnd(now + EXECUTION_MARGIN);
  const ms = Date.parse(executeBy);
  if (Number.isNaN(ms)) {
    throw new Error(
      `--execute-by must be a date, for example 2026-11-15; got "${executeBy}"`,
    );
  }
  const at = BigInt(Math.floor(ms / 1000));
  if (at < now) throw new Error(`--execute-by ${executeBy} is in the past`);
  return capacityWindowEnd(at);
}

/** Registered operators that a batch did not refresh. */
export function unrefreshedOperators(
  registered: string[],
  refreshed: string[],
): string[] {
  const seen = new Set(refreshed.map((operator) => operator.toLowerCase()));
  return registered.filter((operator) => !seen.has(operator.toLowerCase()));
}

/**
 * Operators added from `fromBlock` to `toBlock` that are still registered, but that the batch did
 * not refresh. The connected chain serves this recent range, also on a fork, whose own blocks no
 * public log RPC has.
 */
export async function lateRegistrations(
  provider: ethersLib.Provider,
  ciphernodeRegistry: string,
  isRegistered: (operator: string) => Promise<boolean>,
  fromBlock: number,
  toBlock: number,
  refreshed: string[],
): Promise<string[]> {
  const added = await addedOperators(
    [provider],
    ciphernodeRegistry,
    fromBlock,
    toBlock,
  );
  const registered: string[] = [];
  for (const operator of added) {
    if (await isRegistered(operator)) registered.push(operator);
  }
  return unrefreshedOperators(registered, refreshed);
}

function assertBatchSize(operators: number): void {
  if (operators > MAX_BATCH_OPERATORS) {
    throw new Error(
      `${operators} operators exceed the ${MAX_BATCH_OPERATORS} that one governance transaction refreshes; pause requests and refresh in stages`,
    );
  }
}

const isoTime = (timestamp: bigint) =>
  new Date(Number(timestamp) * 1000).toISOString();

/** The identifier namespace of a verifier with this domain and scope. */
export function identityNamespace(domain: string, scope: string): string {
  return ethersLib.keccak256(
    ethersLib.AbiCoder.defaultAbiCoder().encode(
      ["string", "string", "string"],
      [IDENTITY_TAG, domain, scope],
    ),
  );
}

export interface IdentityGateDecisions {
  bondingRegistry: string;
  /** Upgrade BondingRegistry first when set. */
  upgrade?: { proxyAdmin: string; implementation: string };
  identityRegistry: string;
  required: boolean;
  /** Every registered operator, so that the batch counts their owners again. */
  operators: string[];
}

/** The governance batch: the upgrade, then the policy, then the refresh of every operator. */
export function buildIdentityGateTransactions(
  decisions: IdentityGateDecisions,
): SafeTransaction[] {
  assertBatchSize(decisions.operators.length);
  const txs: SafeTransaction[] = [];
  if (decisions.upgrade) {
    txs.push(
      safeTx(
        decisions.upgrade.proxyAdmin,
        proxyAdminInterface.encodeFunctionData("upgradeAndCall", [
          decisions.bondingRegistry,
          decisions.upgrade.implementation,
          "0x",
        ]),
      ),
    );
  }
  txs.push(
    safeTx(
      decisions.bondingRegistry,
      bondingInterface.encodeFunctionData("setIdentityPolicy", [
        decisions.identityRegistry,
        decisions.required,
      ]),
    ),
  );
  for (
    let start = 0;
    start < decisions.operators.length;
    start += REFRESH_BATCH
  ) {
    txs.push(
      safeTx(
        decisions.bondingRegistry,
        bondingInterface.encodeFunctionData("refreshOperatorStatuses", [
          decisions.operators.slice(start, start + REFRESH_BATCH),
        ]),
      ),
    );
  }
  return txs;
}

/** The verifier settings from the protocol config, checked before any deployment. */
export function identityGateSettings(
  config: ProtocolConfigFile,
): IdentityGateConfig {
  const identity = config.identity;
  if (!identity) {
    throw new Error(
      `${config.name} has no "identity" section; add the ZKPassport verifier settings first`,
    );
  }
  address(identity.zkPassportRootVerifier, "identity.zkPassportRootVerifier");
  for (const [key, value] of [
    ["identity.zkPassportVersion", identity.zkPassportVersion],
    ["identity.oprfKeyHash", identity.oprfKeyHash],
  ] as const) {
    if (!ethersLib.isHexString(value, 32)) {
      throw new Error(`${key} must be a 32-byte hex string`);
    }
  }
  if (identity.zkPassportVersion === ZERO_HASH) {
    throw new Error(
      "identity.zkPassportVersion is unset; use the version that the current ZKPassport app proves",
    );
  }
  if (
    typeof identity.domain !== "string" ||
    typeof identity.scope !== "string" ||
    identity.domain === "" ||
    identity.scope === ""
  ) {
    throw new Error("identity.domain and identity.scope must be set");
  }
  if (typeof identity.faceMatchRequired !== "boolean") {
    throw new Error("identity.faceMatchRequired must be true or false");
  }
  if (identity.nullifierType !== 0 && identity.nullifierType !== 1) {
    throw new Error(
      "identity.nullifierType must be 0 (non-salted) or 1 (salted)",
    );
  }
  if ((identity.nullifierType === 1) !== (identity.oprfKeyHash !== ZERO_HASH)) {
    throw new Error(
      "identity.oprfKeyHash must be ZKPassport's OPRF key hash for salted identifiers and zero otherwise",
    );
  }
  for (const [key, value] of [
    ["identity.proofValidity", identity.proofValidity],
    ["identity.maxValidity", identity.maxValidity],
  ] as const) {
    if (typeof value !== "string" || !/^[1-9]\d*$/.test(value)) {
      throw new Error(`${key} must be a positive number of seconds`);
    }
  }
  if (BigInt(identity.maxValidity) >= 2n ** 48n) {
    throw new Error("identity.maxValidity must fit in uint48");
  }
  return identity;
}

interface IdentityGatePlan {
  name: string;
  chainId: number;
  bondingRegistry: string;
  bondingRegistryProxyAdmin: string;
  bondingImplementation: string;
  libraries: Record<string, string | undefined>;
  identityRegistry: string;
  identityVerifier: string;
  settings: IdentityGateConfig;
  /** Block of the registry deployment: no policy log is older. */
  deployBlock: number;
  operators: number;
  /** The operators that the last written batch refreshes. */
  refreshed: string[];
  /** The last block that the operator list of the last written batch read. */
  writtenBlock: number;
  batches: Record<string, string>;
}

function planPath(config: ProtocolConfigFile): string {
  return path.join(protocolDir, `${config.name}.identity-gate.json`);
}

function batchPath(config: ProtocolConfigFile, stage: string): string {
  return path.join(protocolDir, `${config.name}.identity-${stage}.safe.json`);
}

function loadContext() {
  const config = loadConfig();
  const deployment = readJson<ProtocolDeployment>(deploymentPath(config));
  return { config, deployment };
}

const sameAddress = (a: string, b: string) =>
  a.toLowerCase() === b.toLowerCase();

/** The saved plan, refused when it belongs to another deployment. */
function loadPlan(
  config: ProtocolConfigFile,
  deployment: ProtocolDeployment,
): IdentityGatePlan {
  const plan = readJson<IdentityGatePlan>(planPath(config));
  if (
    plan.name !== config.name ||
    plan.chainId !== config.chainId ||
    !sameAddress(plan.bondingRegistry, deployment.bondingRegistryProxy) ||
    !sameAddress(
      plan.bondingRegistryProxyAdmin,
      config.bondingRegistryProxyAdmin,
    )
  ) {
    throw new Error(
      `${repoRelativePath(planPath(config))} belongs to another deployment than ${config.name}`,
    );
  }
  return plan;
}

async function requireChain(
  ethers: any,
  config: ProtocolConfigFile,
  deployment: ProtocolDeployment,
): Promise<void> {
  const chainId = Number((await ethers.provider.getNetwork()).chainId);
  if (config.chainId !== chainId || deployment.chainId !== chainId) {
    throw new Error(
      `Connected to chain ${chainId}, but ${config.name} is for chain ${config.chainId}`,
    );
  }
}

/** Every registered operator, from the registry's `CiphernodeAdded` history, and the last block read. */
async function registeredOperators(
  ethers: any,
  deployment: ProtocolDeployment,
): Promise<{ operators: string[]; toBlock: number }> {
  const bonding = await ethers.getContractAt(
    "BondingRegistry",
    deployment.bondingRegistryProxy,
  );
  const fromBlock = Number(
    arg("from-block") ?? registryDeployBlock(networkName()) ?? 0,
  );
  const logProviders = (arg("log-rpc") ?? "")
    .split(",")
    .map((url) => url.trim())
    .filter(Boolean)
    .map((url) => new ethersLib.JsonRpcProvider(url));
  // A fork can mine past the head of the log RPCs. The count check below still refuses a history
  // that misses a registered operator.
  const heads = await Promise.all(
    [ethers.provider, ...logProviders].map((provider) =>
      provider.getBlockNumber(),
    ),
  );
  const toBlock = Math.min(...heads);
  const added = await addedOperators(
    logProviders.length > 0 ? logProviders : [ethers.provider],
    deployment.ciphernodeRegistry,
    fromBlock,
    toBlock,
  );
  const operators: string[] = [];
  for (const operator of added) {
    if (await bonding.isRegistered(operator)) operators.push(operator);
  }
  const expected = await bonding.numRegisteredOperators();
  if (BigInt(operators.length) !== expected) {
    throw new Error(
      `The registry history from block ${fromBlock} names ${operators.length} of ${expected} registered operators; pass an earlier --from-block or a --log-rpc with the full history`,
    );
  }
  return { operators, toBlock };
}

/**
 * The distinct owners that a refresh under a required policy would count until `deadline`: owners
 * of active operators whose credential lasts to it. The admission cooldown can still exclude some,
 * so `validate` checks the executed result.
 */
async function countableOwners(
  ethers: any,
  deployment: ProtocolDeployment,
  plan: IdentityGatePlan,
  operators: string[],
  deadline: bigint,
): Promise<number> {
  const bonding = await ethers.getContractAt(
    "BondingRegistry",
    deployment.bondingRegistryProxy,
  );
  const registry = await ethers.getContractAt(
    "OwnerIdentityRegistry",
    plan.identityRegistry,
  );
  const owners = new Set<string>();
  for (const operator of operators) {
    if (!(await bonding.isActive(operator))) continue;
    const owner: string = await bonding.bondOwnerOf(operator);
    const [, expiresAt] = await registry.identityOf(owner);
    if (BigInt(expiresAt) >= deadline) owners.add(owner.toLowerCase());
  }
  return owners.size;
}

/** Write the raw batch, and the Aragon Safe batch when governance is a DAO. */
async function writeBatch(
  config: ProtocolConfigFile,
  stage: string,
  txs: SafeTransaction[],
  description: string,
): Promise<string> {
  const file = batchPath(config, stage);
  const batch = governanceBatch(config, txs);
  batch.meta.name = `${config.name} identity ${stage}`;
  batch.meta.description = description;
  writeJson(file, batch);
  if (config.governance) {
    const safeBuilder = aragonAdminSafeBatch(config, txs);
    safeBuilder.meta.name = batch.meta.name;
    safeBuilder.meta.description = description;
    writeJson(
      governanceSafeBuilderPath({
        ...config,
        name: `${config.name}.identity-${stage}`,
      }),
      safeBuilder,
    );
  }
  if (hasFlag("propose-safe")) {
    await proposeSafeBatch(
      config,
      config.governance ? aragonAdminSafeTransactions(config, txs) : txs,
      config.governance?.proposerSafe ?? config.safe,
    );
  }
  return repoRelativePath(file);
}

export async function prepareIdentityGate(): Promise<void> {
  const { ethers } = await connect();
  const { config, deployment } = loadContext();
  await requireChain(ethers, config, deployment);
  const settings = identityGateSettings(config);
  const [operator] = await ethers.getSigners();
  if (
    !sameAddress(config.bondingRegistryProxy, deployment.bondingRegistryProxy)
  ) {
    throw new Error(
      "The config and the deployment name different BondingRegistry proxies",
    );
  }
  await requireContract(
    ethers.provider,
    settings.zkPassportRootVerifier,
    "ZKPassport root verifier",
  );
  const admin = await ethers.getContractAt(
    "ProxyAdmin",
    config.bondingRegistryProxyAdmin,
  );
  const adminOwner = await admin.owner();
  if (!sameAddress(adminOwner, config.protocolOwner)) {
    throw new Error(
      `BondingRegistry ProxyAdmin owner mismatch: expected ${config.protocolOwner}, got ${adminOwner}`,
    );
  }
  await assertAragonGovernancePreconditions(ethers, config);
  // Discovery reads only existing contracts, so a failure here leaves no deployment behind.
  const { operators, toBlock: writtenBlock } = await registeredOperators(
    ethers,
    deployment,
  );
  assertBatchSize(operators.length);

  const verifierFactory = await ethers.getContractFactory(
    "ZKPassportIdentityVerifier",
  );
  const verifier = await verifierFactory.deploy(
    settings.zkPassportRootVerifier,
    settings.zkPassportVersion,
    settings.domain,
    settings.scope,
    settings.nullifierType,
    settings.oprfKeyHash,
    settings.faceMatchRequired,
    settings.proofValidity,
    settings.maxValidity,
  );
  await verifier.waitForDeployment();
  const identityVerifier = await deployedAddress(verifier);

  // Governance owns the registry from the start: it revokes and replaces the verifier.
  const registryFactory = await ethers.getContractFactory(
    "OwnerIdentityRegistry",
  );
  const registry = await registryFactory.deploy(
    config.protocolOwner,
    identityVerifier,
  );
  await registry.waitForDeployment();
  const identityRegistry = await deployedAddress(registry);
  const deployBlock = (await registry.deploymentTransaction()!.wait())!
    .blockNumber;

  const { implementation, ...libraries } = await deployUpgradeImplementation(
    ethers,
    operator,
    "bondingRegistry",
    deployment,
  );
  const txs = buildIdentityGateTransactions({
    bondingRegistry: deployment.bondingRegistryProxy,
    upgrade: { proxyAdmin: config.bondingRegistryProxyAdmin, implementation },
    identityRegistry,
    required: false,
    operators,
  });
  const prepareBatch = await writeBatch(
    config,
    "prepare",
    txs,
    "Upgrade BondingRegistry, publish the bond-owner identity registry without requiring it, and refresh every operator.",
  );

  const plan: IdentityGatePlan = {
    name: config.name,
    chainId: config.chainId,
    bondingRegistry: deployment.bondingRegistryProxy,
    bondingRegistryProxyAdmin: config.bondingRegistryProxyAdmin,
    bondingImplementation: implementation,
    libraries,
    identityRegistry,
    identityVerifier,
    settings,
    deployBlock,
    operators: operators.length,
    refreshed: operators,
    writtenBlock,
    batches: { prepare: prepareBatch },
  };
  writeJson(planPath(config), plan);
  console.log(`
Identity gate prepared
  verifier:        ${identityVerifier}
  registry:        ${identityRegistry}
  implementation:  ${implementation}
  operators:       ${operators.length}
  governance batch:${prepareBatch} (${txs.length} transactions)
  next:            execute the batch, then run "identityGate.ts validate"
`);
}

/** Write the batch that switches the requirement on (`enforce`) or off (`relax`). */
export async function setIdentityRequirement(required: boolean): Promise<void> {
  const { ethers } = await connect();
  const { config, deployment } = loadContext();
  await requireChain(ethers, config, deployment);
  const plan = loadPlan(config, deployment);
  await assertAragonGovernancePreconditions(ethers, config);
  const { operators, toBlock: writtenBlock } = await registeredOperators(
    ethers,
    deployment,
  );
  // A required policy counts only owners whose credential lasts to the end of the window that
  // executes the batch. Enforcing it with too few would leave requests with zero capacity.
  let deadline: bigint | undefined;
  if (required) {
    const block = await ethers.provider.getBlock("latest");
    if (!block) throw new Error("Could not read the latest block");
    deadline = enforceDeadline(BigInt(block.timestamp), arg("execute-by"));
    const countable = await countableOwners(
      ethers,
      deployment,
      plan,
      operators,
      deadline,
    );
    const needed = requiredActiveOperators(
      config.interfold.committeeThresholds,
      config.chainId,
      arg("sepolia-committee-size"),
    );
    if (BigInt(countable) < needed && !hasFlag("force")) {
      throw new Error(
        `Only ${countable} owners have a credential that lasts to ${isoTime(deadline)}, the end of the capacity window of the latest execution; the largest committee needs ${needed}. Wait for more registrations, pass an earlier --execute-by, or pass --force`,
      );
    }
    console.log(
      `  countable owners: ${countable} (needed ${needed}) for execution by ${isoTime(deadline)}`,
    );
  }
  const txs = buildIdentityGateTransactions({
    bondingRegistry: deployment.bondingRegistryProxy,
    identityRegistry: plan.identityRegistry,
    required,
    operators,
  });
  const stage = required ? "enforce" : "relax";
  plan.batches[stage] = await writeBatch(
    config,
    stage,
    txs,
    deadline !== undefined
      ? `Require a verified bond owner for new committees, and refresh every operator. Execute by ${isoTime(deadline)}.`
      : "Stop requiring a verified bond owner, and refresh every operator.",
  );
  plan.refreshed = operators;
  plan.writtenBlock = writtenBlock;
  writeJson(planPath(config), plan);
  console.log(`
Identity ${stage} batch written
  registry:        ${plan.identityRegistry}
  operators:       ${operators.length}
  governance batch:${plan.batches[stage]} (${txs.length} transactions)${deadline !== undefined ? `\n  execute by:      ${isoTime(deadline)}` : ""}
`);
}

/** Read back the executed batch: contracts, settings, policy, and owner capacity. */
export async function validateIdentityGate(): Promise<void> {
  const { ethers } = await connect();
  const { config, deployment } = loadContext();
  await requireChain(ethers, config, deployment);
  const plan = loadPlan(config, deployment);
  const settings = identityGateSettings(config);
  const expectedRequired = arg("required");
  if (expectedRequired !== "true" && expectedRequired !== "false") {
    throw new Error(
      "Pass --required true|false: the policy that the executed batch set",
    );
  }
  const failures: string[] = [];
  // Addresses and hex values compare in any case; strings compare exactly, because the domain and
  // scope are part of every identifier.
  const expect = (label: string, actual: unknown, expected: unknown) => {
    const hex = (value: unknown) =>
      typeof value === "string" && value.startsWith("0x")
        ? value.toLowerCase()
        : String(value);
    if (hex(actual) !== hex(expected)) {
      failures.push(`${label}: expected ${expected}, read ${actual}`);
    }
  };

  expect(
    "BondingRegistry implementation",
    await proxyImplementation(ethers, plan.bondingRegistry),
    plan.bondingImplementation,
  );
  const registry = await ethers.getContractAt(
    "OwnerIdentityRegistry",
    plan.identityRegistry,
  );
  expect("registry owner", await registry.owner(), config.protocolOwner);
  expect("registry verifier", await registry.verifier(), plan.identityVerifier);
  const verifier = await ethers.getContractAt(
    "ZKPassportIdentityVerifier",
    plan.identityVerifier,
  );
  expect(
    "root verifier",
    await verifier.ROOT_VERIFIER(),
    settings.zkPassportRootVerifier,
  );
  expect("version", await verifier.VERSION(), settings.zkPassportVersion);
  expect("domain", await verifier.domain(), settings.domain);
  expect("scope", await verifier.scope(), settings.scope);
  expect(
    "identifier type",
    await verifier.NULLIFIER_TYPE(),
    settings.nullifierType,
  );
  expect("OPRF key hash", await verifier.OPRF_KEY_HASH(), settings.oprfKeyHash);
  expect(
    "FaceMatch",
    await verifier.FACE_MATCH_REQUIRED(),
    settings.faceMatchRequired,
  );
  expect(
    "proof validity",
    await verifier.PROOF_VALIDITY(),
    settings.proofValidity,
  );
  expect("max validity", await verifier.MAX_VALIDITY(), settings.maxValidity);
  expect(
    "identifier namespace",
    await verifier.IDENTITY_NAMESPACE(),
    identityNamespace(settings.domain, settings.scope),
  );

  const bonding = await ethers.getContractAt(
    "BondingRegistry",
    plan.bondingRegistry,
  );
  // No policy log is older than the registry, so the query starts at its deployment.
  const logs = await bonding.queryFilter(
    bonding.filters.IdentityPolicyUpdated(),
    Number(arg("policy-from-block") ?? plan.deployBlock ?? 0),
  );
  const latest = logs[logs.length - 1] as ethersLib.EventLog | undefined;
  if (!latest) {
    failures.push("BondingRegistry has emitted no IdentityPolicyUpdated");
  } else {
    expect("policy registry", latest.args.registry, plan.identityRegistry);
    expect(
      "policy required",
      latest.args.required,
      expectedRequired === "true",
    );
  }
  if (failures.length > 0) {
    throw new Error(
      `Identity gate validation failed:\n  ${failures.join("\n  ")}`,
    );
  }

  // An operator that registered after the batch read its operator list, and before the batch
  // executed, is not in its refresh, so the policy change left it uncounted. Anyone may refresh it.
  const missing = await lateRegistrations(
    ethers.provider,
    deployment.ciphernodeRegistry,
    (operator) => bonding.isRegistered(operator),
    plan.writtenBlock,
    latest!.blockNumber,
    plan.refreshed,
  );
  if (missing.length > 0) {
    if (!hasFlag("refresh-missing")) {
      throw new Error(
        `${missing.length} operators registered before the batch executed but are not in its refresh: ${missing.join(", ")}. Rerun with --refresh-missing to refresh them from this account (anyone may)`,
      );
    }
    for (let start = 0; start < missing.length; start += REFRESH_BATCH) {
      const chunk = missing.slice(start, start + REFRESH_BATCH);
      const gas = await bonding.refreshOperatorStatuses.estimateGas(chunk);
      await (
        await bonding.refreshOperatorStatuses(chunk, { gasLimit: gas * 2n })
      ).wait();
    }
    plan.refreshed = [...(plan.refreshed ?? []), ...missing];
    writeJson(planPath(config), plan);
    // Capacity reads one second before the head, so check it from a later block.
    console.log(
      `Refreshed ${missing.length} operators: ${missing.join(", ")}. Run validate again to check the capacity.`,
    );
    return;
  }

  const required = requiredActiveOperators(
    config.interfold.committeeThresholds,
    config.chainId,
    arg("sepolia-committee-size"),
  );
  await assertRefreshedOwnerCapacity(bonding, required);
  console.log(`
Identity gate valid
  registry:  ${plan.identityRegistry}
  required:  ${latest!.args.required}
  capacity:  at least ${required} counted owners
`);
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
  const action = process.argv
    .slice(2)
    .find(
      (value) =>
        !value.startsWith("--") &&
        ["prepare", "enforce", "relax", "validate"].includes(value),
    );
  const run =
    action === "prepare"
      ? prepareIdentityGate
      : action === "enforce"
        ? () => setIdentityRequirement(true)
        : action === "relax"
          ? () => setIdentityRequirement(false)
          : action === "validate"
            ? validateIdentityGate
            : undefined;
  if (!run) {
    console.error(
      "Usage: identityGate.ts prepare|enforce|relax|validate [options]",
    );
    process.exitCode = 1;
  } else {
    run()
      .catch((error) => {
        console.error(error);
        process.exitCode = 1;
      })
      .finally(verifyRecordedDeployments);
  }
}
