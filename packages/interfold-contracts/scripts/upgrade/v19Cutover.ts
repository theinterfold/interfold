// SPDX-License-Identifier: LGPL-3.0-only
//
// The v0.19 cutover. Requests are paused and every E3 and committee is drained. One governance
// batch then upgrades Interfold (new libraries, because `ActiveCryptoConfig` changed) and
// CiphernodeRegistryOwnable (its linked `DkgPublicationLib` decodes the `E3` struct, whose
// `CommitteeSize` gained `Large`), registers the BFV parameter sets, installs the BFV verifier
// routers, wires the OpenVM CRISP program, retires the earlier programs and raises the node-release
// policy. Requests stay paused until `resume` builds the unpause batch.
//
//   prepare   deploys the implementation and the BFV routes with the operator key, then writes
//             the plan, the governance batch and the Aragon Safe batch. With `--pause-in-batch`
//             and requests open, the batch pauses requests itself as its first action.
//   validate  checks the chain against the plan after governance executed the batch. It only
//             reads, so it can run any number of times; `--write-records` then updates the
//             deployment record and `deployed_contracts.json`.
//   refresh   refreshes the status of every registered operator that its own release
//             acknowledgment has not refreshed. The new release policy makes every cached status
//             stale, and committee capacity reads zero until each registered operator is refreshed.
//             Anyone can send it; an operator that does not run the release reads as inactive.
//   resume    validates again, checks operator capacity and writes the unpause batch.
import { ethers as ethersLib } from "ethers";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { BFV_PRESETS } from "../../bfv.js";
import { assertRefreshedOwnerCapacity } from "../../tasks/committeeCapacity";
import {
  Interfold__factory as InterfoldFactory,
  NodeReleaseRegistry__factory as NodeReleaseRegistryFactory,
} from "../../types";
import {
  AVAIL_FINALIZATION_WINDOW_SECONDS,
  CRISP_MIN_VOTING_DURATION_SECONDS,
  availVectorXForChain,
} from "../dataAvailability";
import { arg, connect, hasFlag, networkName } from "../protocol/cli";
import { ZERO, proxyAdminInterface } from "../protocol/constants";
import { deployBfvVerifierRoutes } from "../protocol/deployContracts";
import {
  crispDeploymentsPath,
  deploymentPath,
  governanceSafeBuilderPath,
  protocolDir,
  readJson,
  repoRelativePath,
  resolvePath,
  writeJson,
} from "../protocol/files";
import {
  currentNodeRelease,
  requiredCircuitsVersion,
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
  OpenVmGuestIdentity,
  ProtocolConfigFile,
  ProtocolDeployment,
  SafeTransaction,
  TimeoutConfig,
  V19CutoverPlan,
} from "../protocol/types";
import {
  address,
  encodeBfvParams,
  isMissingFunctionError,
  loadConfig,
  requireContract,
  timeoutConfig,
} from "../protocol/values";
import { verifyRecordedDeployments } from "../sourceVerification";
import {
  PRODUCTION_BFV_CONFIG,
  activeBfvConfigForChain,
  bfvConfigsForChain,
  bfvParamSetConfigsForChain,
} from "../utils";
import {
  equalAddress,
  equalValue,
  readContract,
  validateBfvRoutes,
} from "./bfvRouteChecks";
import {
  assertDkgPublicationLibraryLink,
  deployUpgradeImplementation,
  proxyImplementation,
} from "./safeProxyUpgrade";

export const BFV_SCHEME_ID = ethersLib.id("fhe.rs:BFV");
const SUPPORTED_CHAINS = [1, 11155111, 31337];

/** The parameter sets that requests on `chainId` use, as `setParamSet` takes them. */
function chainParamSets(
  chainId: number,
): Array<{ index: number; encoded: string }> {
  return bfvParamSetConfigsForChain(chainId).map((config) => ({
    index: config.paramSet,
    encoded: encodeBfvParams(BFV_PRESETS[config.preset].threshold),
  }));
}

const interfoldInterface = InterfoldFactory.createInterface();
const releaseInterface = NodeReleaseRegistryFactory.createInterface();
const crispInterface = new ethersLib.Interface([
  "function owner() view returns (address)",
  "function interfold() view returns (address)",
  "function imageId() view returns (bytes32)",
  "function openVmVerifier() view returns (address)",
  "function dataAvailabilityVerifier() view returns (address)",
  "function availabilityFinalizationWindow() view returns (uint256)",
  "function MIN_VOTING_DURATION() view returns (uint256)",
  "function inputAvailabilitySigner() view returns (address)",
  "function bindInterfold(address interfold)",
]);
const ciphertextInterface = new ethersLib.Interface([
  "function imageId() view returns (bytes32)",
  "function openVmVerifier() view returns (address)",
]);
const receiptInterface = new ethersLib.Interface([
  "function imageId() view returns (bytes32)",
  "function verifier() view returns (address)",
  "function appExeCommit() view returns (bytes32)",
  "function appVmCommit() view returns (bytes32)",
]);
const dataAvailabilityInterface = new ethersLib.Interface([
  "function bridge() view returns (address)",
  "function vectorx() view returns (address)",
]);

type CrispDeploymentRecord = Record<
  string,
  Record<string, { address?: string }>
>;

type CommitteeThreshold = {
  size: string;
  total: string;
};

/** Selects the operator-capacity gate for a production resume or a named Sepolia rehearsal. */
export function requiredActiveOperators(
  thresholds: CommitteeThreshold[],
  chainId: number,
  rehearsalCommitteeSize?: string,
): bigint {
  if (rehearsalCommitteeSize !== undefined) {
    if (chainId !== 11155111) {
      throw new Error(
        "A reduced committee-capacity gate is available only for a Sepolia rehearsal",
      );
    }
    if (!/^\d+$/.test(rehearsalCommitteeSize)) {
      throw new Error("The rehearsal committee size must be an integer ID");
    }
    const selected = thresholds.find(
      (threshold) => threshold.size === rehearsalCommitteeSize,
    );
    if (!selected) {
      throw new Error(
        `Committee size ${rehearsalCommitteeSize} is not configured`,
      );
    }
    return BigInt(selected.total);
  }

  return thresholds.reduce((maximum, threshold) => {
    const total = BigInt(threshold.total);
    return total > maximum ? total : maximum;
  }, 0n);
}

function planPath(config: ProtocolConfigFile): string {
  return arg("plan")
    ? resolvePath(arg("plan")!)
    : path.join(protocolDir, `${config.name}.v19-cutover.json`);
}

function batchPath(config: ProtocolConfigFile, stage: string): string {
  return path.join(protocolDir, `${config.name}.v19-${stage}.safe.json`);
}

/** The decisions that `prepare` reads from the chain; the batch follows from them alone. */
export interface V19CutoverDecisions {
  /** Pause requests as the first action (`--pause-in-batch` while requests are open). */
  pauseRequests?: boolean;
  interfold: string;
  interfoldProxyAdmin: string;
  interfoldImplementation: string;
  registry: string;
  registryProxyAdmin: string;
  registryImplementation: string;
  /** The chain's parameter sets that are not registered yet. */
  paramSets: Array<{ index: number; encoded: string }>;
  committeeThresholds: Array<{ size: bigint; quorum: bigint; total: bigint }>;
  pkVerifier: string;
  decryptionVerifier: string;
  /** Present when the scheme's ciphertext verifier differs from CRISP's. */
  ciphertextVerifier?: string;
  /** Present when the CRISP program is not registered yet. */
  registerProgram?: string;
  retirePrograms: string[];
  /** Present when the CRISP program is not bound to Interfold yet. */
  bindProgram?: string;
  nodeReleaseRegistry: string;
  /** Present when the on-chain release policy differs from this release. */
  nodeRelease?: { protocolVersion: number; nodeGeneration: number };
}

/**
 * The cutover batch in execution order. The Interfold upgrade comes first, because the new
 * implementation checks the parameter set and the verifiers against its own `ActiveCryptoConfig`.
 * The registry upgrade follows it and comes before every Large threshold: a registry that predates
 * `Large` rejects a size-3 E3 when it decodes the `E3` struct. CRISP is registered before it is
 * bound, and the release policy, which needs paused requests, comes last.
 */
export function buildV19CutoverTransactions(
  decisions: V19CutoverDecisions,
): SafeTransaction[] {
  const call = (functionName: string, args: unknown[]) =>
    safeTx(
      decisions.interfold,
      interfoldInterface.encodeFunctionData(functionName as any, args as any),
    );
  const txs: SafeTransaction[] = [];
  if (decisions.pauseRequests) {
    txs.push(call("setRequestsPaused", [true]));
    // prepare checked the drain while requests were open. The release setter checks it again on
    // chain; without that action, the batch asks the registry directly.
    if (!decisions.nodeRelease) {
      txs.push(
        safeTx(
          decisions.nodeReleaseRegistry,
          releaseInterface.encodeFunctionData("assertUpgradeWindow"),
        ),
      );
    }
  }
  txs.push(
    safeTx(
      decisions.interfoldProxyAdmin,
      proxyAdminInterface.encodeFunctionData("upgradeAndCall", [
        decisions.interfold,
        decisions.interfoldImplementation,
        "0x",
      ]),
    ),
    safeTx(
      decisions.registryProxyAdmin,
      proxyAdminInterface.encodeFunctionData("upgradeAndCall", [
        decisions.registry,
        decisions.registryImplementation,
        "0x",
      ]),
    ),
  );
  for (const paramSet of decisions.paramSets) {
    txs.push(call("setParamSet", [paramSet.index, paramSet.encoded]));
  }
  for (const threshold of decisions.committeeThresholds) {
    txs.push(
      call("setCommitteeThresholds", [
        threshold.size,
        [threshold.quorum, threshold.total],
      ]),
    );
  }
  txs.push(
    call("setPkVerifier", [BFV_SCHEME_ID, decisions.pkVerifier]),
    call("setDecryptionVerifier", [
      BFV_SCHEME_ID,
      decisions.decryptionVerifier,
    ]),
  );
  if (decisions.ciphertextVerifier) {
    txs.push(
      call("setCiphertextVerifier", [
        BFV_SCHEME_ID,
        decisions.ciphertextVerifier,
      ]),
    );
  }
  if (decisions.registerProgram) {
    txs.push(call("registerE3Program", [decisions.registerProgram]));
  }
  for (const program of decisions.retirePrograms) {
    txs.push(call("unregisterE3Program", [program]));
  }
  if (decisions.bindProgram) {
    txs.push(
      safeTx(
        decisions.bindProgram,
        crispInterface.encodeFunctionData("bindInterfold", [
          decisions.interfold,
        ]),
      ),
    );
  }
  if (decisions.nodeRelease) {
    txs.push(
      safeTx(
        decisions.nodeReleaseRegistry,
        releaseInterface.encodeFunctionData("setRequiredNodeRelease", [
          decisions.nodeRelease.protocolVersion,
          decisions.nodeRelease.nodeGeneration,
        ]),
      ),
    );
  }
  return txs;
}

/** Read the expected OpenVM guest identity, from `--openvm-identity <json>`. */
export function readOpenVmIdentity(file: string): OpenVmGuestIdentity {
  const raw = JSON.parse(fs.readFileSync(resolvePath(file), "utf8"));
  const identity: OpenVmGuestIdentity = {
    appExeCommit: String(raw.appExeCommit ?? ""),
    appVmCommit: String(raw.appVmCommit ?? ""),
    halo2RuntimeCodeHash: String(raw.halo2RuntimeCodeHash ?? ""),
  };
  for (const [name, value] of Object.entries(identity)) {
    if (!/^0x[0-9a-fA-F]{64}$/.test(value)) {
      throw new Error(`OpenVM identity ${name} must be a 32-byte hex value`);
    }
  }
  return identity;
}

/** The CRISP contracts that the CRISP deployment recorded for `network`. */
function readCrispRecord(
  network: string,
  record?: string,
): CrispDeploymentRecord[string] {
  const deployment = readJson<CrispDeploymentRecord>(
    crispDeploymentsPath(record),
  )[network];
  if (!deployment) {
    throw new Error(`No CRISP deployment is recorded for ${network}`);
  }
  return deployment;
}

/** The CRISP contracts that the batch wires, from the CRISP deployment record. */
export function resolveOpenVmCrisp(
  network = networkName(),
  record?: string,
): {
  crispProgram: string;
  ciphertextVerifier: string;
  dataAvailabilityVerifier: string;
  availDataAvailability: boolean;
} {
  const deployment = readCrispRecord(network, record);
  return {
    crispProgram: address(
      deployment.CRISPProgram?.address ?? "",
      "CRISPProgram",
    ),
    ciphertextVerifier: address(
      deployment.OpenVmBfvCiphertextVerifier?.address ?? "",
      "OpenVmBfvCiphertextVerifier",
    ),
    dataAvailabilityVerifier: address(
      deployment.AvailVectorXDataAvailabilityVerifier?.address ??
        deployment.MockCrispDataAvailabilityVerifier?.address ??
        "",
      "DataAvailabilityVerifier",
    ),
    availDataAvailability: Boolean(
      deployment.AvailVectorXDataAvailabilityVerifier?.address,
    ),
  };
}

/**
 * Check that CRISP, its ciphertext verifier and its receipt verifier name one OpenVM guest, that
 * the guest is `expected`, and that CRISP's data availability matches the chain. `interfold` is the
 * proxy that CRISP may already be bound to. Returns the receipt verifier and the image ID.
 */
export async function checkOpenVmCrisp(
  ethers: any,
  chainId: number,
  addresses: {
    crispProgram: string;
    ciphertextVerifier: string;
    dataAvailabilityVerifier: string;
    availDataAvailability: boolean;
    interfold: string;
    protocolOwner: string;
    inputAvailabilitySigner?: string;
  },
  expected: OpenVmGuestIdentity | undefined,
): Promise<{
  receiptVerifier: string;
  imageId: string;
  inputAvailabilitySigner: string;
  bound: boolean;
}> {
  const provider = ethers.provider;
  const crisp = addresses.crispProgram;
  await Promise.all([
    requireContract(provider, crisp, "CRISP program"),
    requireContract(
      provider,
      addresses.ciphertextVerifier,
      "CRISP ciphertext verifier",
    ),
    requireContract(
      provider,
      addresses.dataAvailabilityVerifier,
      "CRISP data-availability verifier",
    ),
  ]);
  const read = (target: string, iface: ethersLib.Interface, name: string) =>
    readContract(provider, target, iface, name);

  equalAddress(
    String(await read(crisp, crispInterface, "owner")),
    addresses.protocolOwner,
    "CRISP owner",
  );
  const boundInterfold = String(await read(crisp, crispInterface, "interfold"));
  if (
    boundInterfold.toLowerCase() !== ZERO.toLowerCase() &&
    boundInterfold.toLowerCase() !== addresses.interfold.toLowerCase()
  ) {
    throw new Error(`CRISP is already bound to ${boundInterfold}`);
  }

  const receiptVerifier = String(
    await read(crisp, crispInterface, "openVmVerifier"),
  );
  await requireContract(provider, receiptVerifier, "OpenVM receipt verifier");
  equalAddress(
    String(
      await read(
        addresses.ciphertextVerifier,
        ciphertextInterface,
        "openVmVerifier",
      ),
    ),
    receiptVerifier,
    "CRISP ciphertext verifier receipt verifier",
  );
  const imageId = String(await read(crisp, crispInterface, "imageId"));
  equalValue(
    await read(addresses.ciphertextVerifier, ciphertextInterface, "imageId"),
    imageId,
    "CRISP ciphertext verifier image ID",
  );
  equalValue(
    await read(receiptVerifier, receiptInterface, "imageId"),
    imageId,
    "OpenVM receipt verifier image ID",
  );
  if (expected) {
    equalValue(
      await read(receiptVerifier, receiptInterface, "appExeCommit"),
      expected.appExeCommit,
      "OpenVM application executable commitment",
    );
    equalValue(
      await read(receiptVerifier, receiptInterface, "appVmCommit"),
      expected.appVmCommit,
      "OpenVM VM commitment",
    );
    const halo2 = String(
      await read(receiptVerifier, receiptInterface, "verifier"),
    );
    equalValue(
      ethersLib.keccak256(await provider.getCode(halo2)),
      expected.halo2RuntimeCodeHash,
      "OpenVM Halo2 verifier runtime code hash",
    );
  } else if (chainId === 1) {
    throw new Error(
      "Mainnet needs the release's OpenVM guest identity: pass --openvm-identity <json>",
    );
  }

  equalAddress(
    String(await read(crisp, crispInterface, "dataAvailabilityVerifier")),
    addresses.dataAvailabilityVerifier,
    "CRISP data-availability verifier",
  );
  if (chainId === 1 && !addresses.availDataAvailability) {
    throw new Error("Mainnet CRISP needs the Avail data-availability verifier");
  }
  if (addresses.availDataAvailability) {
    const avail = availVectorXForChain(chainId);
    equalAddress(
      String(
        await read(
          addresses.dataAvailabilityVerifier,
          dataAvailabilityInterface,
          "bridge",
        ),
      ),
      avail.bridge,
      "CRISP Avail bridge",
    );
    equalAddress(
      String(
        await read(
          addresses.dataAvailabilityVerifier,
          dataAvailabilityInterface,
          "vectorx",
        ),
      ),
      avail.vectorx,
      "CRISP VectorX",
    );
    equalValue(
      await read(crisp, crispInterface, "availabilityFinalizationWindow"),
      AVAIL_FINALIZATION_WINDOW_SECONDS,
      "CRISP availability finalization window",
    );
  }
  equalValue(
    await read(crisp, crispInterface, "MIN_VOTING_DURATION"),
    CRISP_MIN_VOTING_DURATION_SECONDS,
    "CRISP minimum voting duration",
  );
  const inputAvailabilitySigner = String(
    await read(crisp, crispInterface, "inputAvailabilitySigner"),
  );
  if (addresses.inputAvailabilitySigner) {
    equalAddress(
      inputAvailabilitySigner,
      addresses.inputAvailabilitySigner,
      "CRISP input availability signer",
    );
  }
  return {
    receiptVerifier,
    imageId,
    inputAvailabilitySigner,
    bound: boundInterfold.toLowerCase() === addresses.interfold.toLowerCase(),
  };
}

async function requireDrainedAndPaused(
  interfold: any,
  registry: any,
): Promise<void> {
  if (!(await interfold.requestsPaused())) {
    throw new Error("Pause E3 requests before the cutover");
  }
  await requireDrained(interfold, registry);
}

async function requireDrained(interfold: any, registry: any): Promise<void> {
  const [activeE3s, unreleased] = await Promise.all([
    interfold.activeE3Count(),
    registry.unreleasedCommitteeCount(),
  ]);
  if (activeE3s !== 0n || unreleased !== 0n) {
    throw new Error(
      `The cutover needs a drained protocol: active E3s ${activeE3s}, unreleased committees ${unreleased}. Release every committee whose E3 ended (CiphernodeRegistry.releaseCommittee) first.`,
    );
  }
}

function loadContext() {
  const config = loadConfig();
  const deployment = readJson<ProtocolDeployment>(deploymentPath(config));
  return { config, deployment };
}

async function requireSupportedChain(
  ethers: any,
  config: ProtocolConfigFile,
  deployment: ProtocolDeployment,
): Promise<number> {
  const chainId = Number((await ethers.provider.getNetwork()).chainId);
  if (
    !SUPPORTED_CHAINS.includes(chainId) ||
    config.chainId !== chainId ||
    deployment.chainId !== chainId
  ) {
    throw new Error(
      `The v0.19 cutover needs a matching config and deployment for chain ${chainId}`,
    );
  }
  if (chainId === 1 && !config.governance) {
    throw new Error("Aragon governance is required for the mainnet cutover");
  }
  return chainId;
}

export async function prepareV19Cutover(): Promise<V19CutoverPlan> {
  const { ethers } = await connect();
  const { config, deployment } = loadContext();
  const chainId = await requireSupportedChain(ethers, config, deployment);
  const identity = arg("openvm-identity")
    ? readOpenVmIdentity(arg("openvm-identity")!)
    : undefined;

  const interfold = await ethers.getContractAt(
    "Interfold",
    deployment.interfold,
  );
  const registry = await ethers.getContractAt(
    "CiphernodeRegistryOwnable",
    deployment.ciphernodeRegistry,
  );
  const releases = await ethers.getContractAt(
    "NodeReleaseRegistry",
    deployment.nodeReleaseRegistry,
  );
  equalAddress(
    String(await interfold.owner()),
    config.protocolOwner,
    "Interfold owner",
  );
  const proxyAdmin = await ethers.getContractAt(
    "ProxyAdmin",
    deployment.interfoldProxyAdmin,
  );
  equalAddress(
    String(await proxyAdmin.owner()),
    config.protocolOwner,
    "Interfold ProxyAdmin owner",
  );
  const registryAdmin = await ethers.getContractAt(
    "ProxyAdmin",
    deployment.ciphernodeRegistryProxyAdmin,
  );
  equalAddress(
    String(await registryAdmin.owner()),
    config.protocolOwner,
    "CiphernodeRegistry ProxyAdmin owner",
  );
  // `--pause-in-batch` lets governance sign the pause and the cutover once: the batch pauses
  // requests as its first action. The drain check then holds only when prepare runs, so read
  // `activeE3Count` and `unreleasedCommitteeCount` again right before the batch executes.
  const pauseRequests =
    hasFlag("pause-in-batch") && !(await interfold.requestsPaused());
  if (pauseRequests) {
    await requireDrained(interfold, registry);
  } else {
    await requireDrainedAndPaused(interfold, registry);
  }

  // A stale record would make the plan describe a different upgrade than the one executed.
  const liveImplementation = await proxyImplementation(
    ethers,
    deployment.interfold,
  );
  if (
    liveImplementation.toLowerCase() !==
    deployment.interfoldImplementation.toLowerCase()
  ) {
    throw new Error(
      `Interfold deployment record is stale: recorded ${deployment.interfoldImplementation}, live ${liveImplementation}`,
    );
  }
  const liveRegistryImplementation = await proxyImplementation(
    ethers,
    deployment.ciphernodeRegistry,
  );
  if (
    liveRegistryImplementation.toLowerCase() !==
    deployment.ciphernodeRegistryImplementation.toLowerCase()
  ) {
    throw new Error(
      `CiphernodeRegistry deployment record is stale: recorded ${deployment.ciphernodeRegistryImplementation}, live ${liveRegistryImplementation}`,
    );
  }

  const nodeRelease = currentNodeRelease();
  const circuitsVersion = requiredCircuitsVersion();
  if (nodeRelease.version !== circuitsVersion) {
    throw new Error(
      `The release and its circuit archive differ: source version ${nodeRelease.version}, circuit archive ${circuitsVersion}`,
    );
  }
  const [requiredProtocolVersion, requiredNodeGeneration] = await Promise.all([
    releases.requiredProtocolVersion(),
    releases.requiredNodeGeneration(),
  ]);
  const nodeReleasePolicyUpdated = requiresNodeReleasePolicyUpdate(
    nodeRelease,
    requiredProtocolVersion,
    requiredNodeGeneration,
  );

  // Sepolia requests use the insecure set too, so the batch registers every set the chain lacks.
  const missingParamSets: V19CutoverDecisions["paramSets"] = [];
  for (const paramSet of chainParamSets(chainId)) {
    const registered: string = await interfold.paramSetRegistry(paramSet.index);
    if (registered === "0x") {
      missingParamSets.push(paramSet);
    } else if (registered.toLowerCase() !== paramSet.encoded.toLowerCase()) {
      throw new Error(
        `Parameter set ${paramSet.index} is registered with other values; registration is append-only, so this deployment cannot take the release's parameters`,
      );
    }
  }

  const thresholds: V19CutoverDecisions["committeeThresholds"] = [];
  for (const threshold of config.interfold.committeeThresholds) {
    const size = BigInt(threshold.size);
    const current = await readCommitteeThreshold(
      (index) => interfold.committeeThresholds(size, index),
      size,
      SIZES_ADDED_BY_RELEASE,
    );
    if (
      !current ||
      current[0] !== BigInt(threshold.quorum) ||
      current[1] !== BigInt(threshold.total)
    ) {
      thresholds.push({
        size,
        quorum: BigInt(threshold.quorum),
        total: BigInt(threshold.total),
      });
    }
  }

  const crispAddresses = resolveOpenVmCrisp();
  const inputAvailabilitySigner =
    arg("input-availability-signer") ?? process.env.INPUT_AVAILABILITY_SIGNER;
  const crisp = await checkOpenVmCrisp(
    ethers,
    chainId,
    {
      ...crispAddresses,
      interfold: deployment.interfold,
      protocolOwner: config.protocolOwner,
      inputAvailabilitySigner: inputAvailabilitySigner
        ? address(inputAvailabilitySigner, "input availability signer")
        : undefined,
    },
    identity,
  );

  const retirementCandidates = new Map<string, string>();
  for (const program of [
    deployment.initialE3Program,
    deployment.crispProgram,
    ...(config.upgrade?.retireE3Programs ?? []),
  ]) {
    if (!program) continue;
    const checked = address(program, "retired E3 program");
    if (checked.toLowerCase() === crispAddresses.crispProgram.toLowerCase()) {
      continue;
    }
    retirementCandidates.set(checked.toLowerCase(), checked);
  }
  const retiredE3Programs: string[] = [];
  for (const program of retirementCandidates.values()) {
    if (await interfold.e3Programs(program)) retiredE3Programs.push(program);
  }

  const [operator] = await ethers.getSigners();
  const deployFromBlock = (await ethers.provider.getBlockNumber()) + 1;
  const upgrade = await deployUpgradeImplementation(
    ethers,
    operator,
    "interfold",
    deployment,
  );
  if (!upgrade.lifecycleLibrary || !upgrade.pricingLibrary) {
    throw new Error("Interfold libraries were not deployed");
  }
  const registryUpgrade = await deployUpgradeImplementation(
    ethers,
    operator,
    "ciphernodeRegistry",
    deployment,
  );
  if (
    !registryUpgrade.sortitionLibrary ||
    !registryUpgrade.dkgPublicationLibrary
  ) {
    throw new Error("Registry libraries were not deployed");
  }
  const routes = await deployBfvVerifierRoutes(
    ethers,
    deployment.ciphernodeRegistry,
    activeBfvConfigForChain(chainId),
    bfvConfigsForChain(chainId),
  );

  const currentCiphertextVerifier = String(
    await interfold.getCiphertextVerifier(BFV_SCHEME_ID),
  );
  const txs = buildV19CutoverTransactions({
    pauseRequests,
    interfold: deployment.interfold,
    interfoldProxyAdmin: deployment.interfoldProxyAdmin,
    interfoldImplementation: upgrade.implementation,
    registry: deployment.ciphernodeRegistry,
    registryProxyAdmin: deployment.ciphernodeRegistryProxyAdmin,
    registryImplementation: registryUpgrade.implementation,
    paramSets: missingParamSets,
    committeeThresholds: thresholds,
    pkVerifier: routes.pkVerifier,
    decryptionVerifier: routes.decryptionVerifier,
    ciphertextVerifier:
      currentCiphertextVerifier.toLowerCase() ===
      crispAddresses.ciphertextVerifier.toLowerCase()
        ? undefined
        : crispAddresses.ciphertextVerifier,
    registerProgram: (await interfold.e3Programs(crispAddresses.crispProgram))
      ? undefined
      : crispAddresses.crispProgram,
    retirePrograms: retiredE3Programs,
    bindProgram: crisp.bound ? undefined : crispAddresses.crispProgram,
    nodeReleaseRegistry: deployment.nodeReleaseRegistry,
    nodeRelease: nodeReleasePolicyUpdated ? nodeRelease : undefined,
  });

  const rawBatchFile = batchPath(config, "cutover");
  const title = `${config.name} v0.19 cutover`;
  const description = `${pauseRequests ? "Pause requests, then u" : "U"}pgrade Interfold and CiphernodeRegistryOwnable, register the BFV parameters, install the BFV routers, wire the OpenVM CRISP program and raise the node release while requests stay paused.`;
  const batch = governanceBatch(config, txs);
  batch.meta.name = title;
  batch.meta.description = description;
  writeJson(rawBatchFile, batch);
  let safeBuilderFile: string | undefined;
  if (config.governance) {
    safeBuilderFile = governanceSafeBuilderPath({
      ...config,
      name: `${config.name}.v19-cutover`,
    });
    const safeBatch = aragonAdminSafeBatch(config, txs);
    safeBatch.meta.name = title;
    safeBatch.meta.description = description;
    writeJson(safeBuilderFile, safeBatch);
  }

  const plan: V19CutoverPlan = {
    name: config.name,
    chainId,
    operator: await operator.getAddress(),
    protocolOwner: config.protocolOwner,
    interfoldProxy: deployment.interfold,
    interfoldProxyAdmin: deployment.interfoldProxyAdmin,
    previousInterfoldImplementation: liveImplementation,
    interfoldImplementation: upgrade.implementation,
    deployFromBlock,
    lifecycleLibrary: upgrade.lifecycleLibrary,
    pricingLibrary: upgrade.pricingLibrary,
    registryProxy: deployment.ciphernodeRegistry,
    registryProxyAdmin: deployment.ciphernodeRegistryProxyAdmin,
    previousRegistryImplementation: liveRegistryImplementation,
    registryImplementation: registryUpgrade.implementation,
    registrySortitionLibrary: registryUpgrade.sortitionLibrary,
    dkgPublicationLibrary: registryUpgrade.dkgPublicationLibrary,
    nodeReleaseRegistry: deployment.nodeReleaseRegistry,
    nodeRelease,
    nodeReleasePolicyUpdated,
    cryptoConfigId: PRODUCTION_BFV_CONFIG.configId,
    paramSetsRegisteredByBatch: missingParamSets.map(({ index }) => index),
    pkVerifier: routes.pkVerifier,
    decryptionVerifier: routes.decryptionVerifier,
    bfvVerifierRoutes: routes.bfvVerifierRoutes,
    ciphertextVerifier: crispAddresses.ciphertextVerifier,
    openVmReceiptVerifier: crisp.receiptVerifier,
    openVmIdentity: identity ?? {
      appExeCommit: String(
        await readContract(
          ethers.provider,
          crisp.receiptVerifier,
          receiptInterface,
          "appExeCommit",
        ),
      ),
      appVmCommit: String(
        await readContract(
          ethers.provider,
          crisp.receiptVerifier,
          receiptInterface,
          "appVmCommit",
        ),
      ),
      halo2RuntimeCodeHash: ethersLib.keccak256(
        await ethers.provider.getCode(
          String(
            await readContract(
              ethers.provider,
              crisp.receiptVerifier,
              receiptInterface,
              "verifier",
            ),
          ),
        ),
      ),
    },
    crispProgram: crispAddresses.crispProgram,
    crispImageId: crisp.imageId,
    retiredE3Programs,
    dataAvailabilityVerifier: crispAddresses.dataAvailabilityVerifier,
    availDataAvailability: crispAddresses.availDataAvailability,
    inputAvailabilitySigner: crisp.inputAvailabilitySigner,
    safeTransactions: repoRelativePath(rawBatchFile),
    governanceSafeBuilder: safeBuilderFile
      ? repoRelativePath(safeBuilderFile)
      : undefined,
  };
  // The plan records the contracts that this run deployed, so it is written before the proposal
  // can fail.
  writeJson(planPath(config), plan);
  if (hasFlag("propose-safe")) {
    plan.safeProposal = config.governance
      ? await proposeSafeBatch(
          config,
          aragonAdminSafeTransactions(config, txs),
          config.governance.proposerSafe,
        )
      : await proposeSafeBatch(config, txs);
    writeJson(planPath(config), plan);
  }

  console.log(`
v0.19 cutover prepared
  Interfold implementation: ${plan.interfoldImplementation} (was ${plan.previousInterfoldImplementation})
  registry implementation:  ${plan.registryImplementation} (was ${plan.previousRegistryImplementation})
  PK verifier router:       ${plan.pkVerifier}
  decryption router:        ${plan.decryptionVerifier}
  BFV routes:               ${plan.bfvVerifierRoutes.length}
  parameter sets:           ${plan.paramSetsRegisteredByBatch.length ? `${plan.paramSetsRegisteredByBatch.join(", ")} registered by the batch` : "already registered"}
  CRISP program:            ${plan.crispProgram} (image ${plan.crispImageId})
  ciphertext verifier:      ${plan.ciphertextVerifier}
  retired E3 programs:      ${plan.retiredE3Programs.join(", ") || "none"}
  node release:             ${plan.nodeRelease.version} (protocol ${plan.nodeRelease.protocolVersion}, generation ${plan.nodeRelease.nodeGeneration})${plan.nodeReleasePolicyUpdated ? "" : " already required"}
  governance batch:         ${plan.safeTransactions} (${txs.length} transactions)
  Aragon Safe batch:        ${plan.governanceSafeBuilder ?? "not configured"}
  requests:                 ${pauseRequests ? "paused by the batch (first action); check activeE3Count and unreleasedCommitteeCount are 0 right before it executes" : "already paused"}; they remain paused after execution
`);
  return plan;
}

/** `CommitteeSize` values this release appends: `Large` (3). */
export const SIZES_ADDED_BY_RELEASE: readonly bigint[] = [3n];

/**
 * Read the live `(quorum, total)` of a committee size, or `undefined` when the implementation that
 * the batch replaces lacks the size: it reverts without data on a size its `CommitteeSize` enum does
 * not have. The batch upgrades first, so it can then set that size. Only a size this release adds
 * (`addedSizes`) may read as unset; for every other size the error is rethrown.
 */
export async function readCommitteeThreshold(
  read: (index: bigint) => Promise<bigint>,
  size: bigint,
  addedSizes: readonly bigint[],
): Promise<[bigint, bigint] | undefined> {
  try {
    return await Promise.all([read(0n), read(1n)]);
  } catch (error) {
    if (isMissingFunctionError(error) && addedSizes.includes(size)) {
      return undefined;
    }
    throw error;
  }
}

/**
 * Require the live E3 windows to equal the configured ones. The cutover batch does not set them, so
 * a chain whose governance skipped the manual `setTimeoutConfig` (Sepolia: `dkgWindow` 1800 s, where
 * a Large committee needs 7200 s) must not resume.
 */
export function requireTimeoutConfig(
  live: { dkgWindow: bigint; computeWindow: bigint; decryptionWindow: bigint },
  configured: TimeoutConfig,
): void {
  const expected = timeoutConfig(configured);
  for (const window of [
    "dkgWindow",
    "computeWindow",
    "decryptionWindow",
  ] as const) {
    if (live[window] !== expected[window]) {
      throw new Error(
        `Interfold ${window} is ${live[window]} s; the configuration sets ${expected[window]} s. Execute setTimeoutConfig with the configured windows before resume`,
      );
    }
  }
}

/**
 * Require the live registry proxy to run the planned implementation, and that implementation to
 * link the planned `DkgPublicationLib`. A registry that predates `Large` reverts in `publishCommittee`
 * for every size-3 E3, so `validate` and `resume` must fail while it is in place.
 */
export async function requireV19RegistryUpgrade(
  ethers: { provider: ethersLib.Provider },
  plan: Pick<
    V19CutoverPlan,
    "registryProxy" | "registryImplementation" | "dkgPublicationLibrary"
  >,
): Promise<void> {
  equalAddress(
    await proxyImplementation(ethers, plan.registryProxy),
    plan.registryImplementation,
    "CiphernodeRegistry implementation",
  );
  await assertDkgPublicationLibraryLink(
    ethers.provider,
    plan.registryImplementation,
    plan.dkgPublicationLibrary,
  );
}

/**
 * Check the executed cutover against the plan. Reads only, so it can run before resume and again
 * after it. `--write-records` copies the new addresses into both deployment records.
 */
export async function validateV19Cutover(): Promise<V19CutoverPlan> {
  const { ethers } = await connect();
  const { config, deployment } = loadContext();
  const chainId = await requireSupportedChain(ethers, config, deployment);
  const plan = readJson<V19CutoverPlan>(planPath(config));
  if (
    plan.chainId !== chainId ||
    plan.interfoldProxy.toLowerCase() !== deployment.interfold.toLowerCase()
  ) {
    throw new Error("The cutover plan belongs to another deployment");
  }
  const interfold = await ethers.getContractAt(
    "Interfold",
    plan.interfoldProxy,
  );
  const registry = await ethers.getContractAt(
    "CiphernodeRegistryOwnable",
    plan.registryProxy,
  );
  const releases = await ethers.getContractAt(
    "NodeReleaseRegistry",
    plan.nodeReleaseRegistry,
  );

  equalAddress(
    await proxyImplementation(ethers, plan.interfoldProxy),
    plan.interfoldImplementation,
    "Interfold implementation",
  );
  await requireV19RegistryUpgrade(ethers, plan);
  equalValue(
    await interfold.activeCryptoConfigId(),
    plan.cryptoConfigId,
    "Interfold crypto configuration",
  );
  for (const paramSet of chainParamSets(chainId)) {
    equalValue(
      await interfold.paramSetRegistry(paramSet.index),
      paramSet.encoded,
      `parameter set ${paramSet.index}`,
    );
  }
  for (const threshold of config.interfold.committeeThresholds) {
    const size = BigInt(threshold.size);
    equalValue(
      await interfold.committeeThresholds(size, 0n),
      threshold.quorum,
      `committee ${threshold.size} quorum`,
    );
    equalValue(
      await interfold.committeeThresholds(size, 1n),
      threshold.total,
      `committee ${threshold.size} total`,
    );
  }
  requireTimeoutConfig(
    await interfold.getTimeoutConfig(),
    config.interfold.timeoutConfig,
  );
  equalAddress(
    String(await interfold.getPkVerifier(BFV_SCHEME_ID)),
    plan.pkVerifier,
    "BFV PK verifier",
  );
  equalAddress(
    String(await interfold.getDecryptionVerifier(BFV_SCHEME_ID)),
    plan.decryptionVerifier,
    "BFV decryption verifier",
  );
  await validateBfvRoutes(ethers, chainId, {
    pkVerifier: plan.pkVerifier,
    decryptionVerifier: plan.decryptionVerifier,
    bfvVerifierRoutes: plan.bfvVerifierRoutes,
    registry: plan.registryProxy,
  });

  equalAddress(
    String(await interfold.getCiphertextVerifier(BFV_SCHEME_ID)),
    plan.ciphertextVerifier,
    "BFV ciphertext verifier",
  );
  const crisp = await checkOpenVmCrisp(
    ethers,
    chainId,
    {
      crispProgram: plan.crispProgram,
      ciphertextVerifier: plan.ciphertextVerifier,
      dataAvailabilityVerifier: plan.dataAvailabilityVerifier,
      availDataAvailability: plan.availDataAvailability,
      interfold: plan.interfoldProxy,
      protocolOwner: plan.protocolOwner,
      inputAvailabilitySigner: plan.inputAvailabilitySigner,
    },
    plan.openVmIdentity,
  );
  if (!crisp.bound) throw new Error("CRISP is not bound to Interfold");
  equalValue(crisp.imageId, plan.crispImageId, "CRISP image ID");
  if (!(await interfold.e3Programs(plan.crispProgram))) {
    throw new Error("CRISP is not a registered E3 program");
  }
  for (const program of plan.retiredE3Programs) {
    if (await interfold.e3Programs(program)) {
      throw new Error(`Retired E3 program is still registered: ${program}`);
    }
  }

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
  const paused = await interfold.requestsPaused();
  if (paused) await requireDrainedAndPaused(interfold, registry);

  if (hasFlag("write-records")) {
    deployment.interfoldImplementation = plan.interfoldImplementation;
    deployment.ciphernodeRegistryImplementation = plan.registryImplementation;
    deployment.registrySortitionLib = plan.registrySortitionLibrary;
    deployment.dkgPublicationLib = plan.dkgPublicationLibrary;
    deployment.interfoldLifecycle = plan.lifecycleLibrary;
    deployment.interfoldPricing = plan.pricingLibrary;
    deployment.pkVerifier = plan.pkVerifier;
    deployment.decryptionVerifier = plan.decryptionVerifier;
    deployment.ciphertextVerifier = plan.ciphertextVerifier;
    deployment.crispProgram = plan.crispProgram;
    deployment.dataAvailabilityVerifier = plan.dataAvailabilityVerifier;
    deployment.bfvVerifierRoutes = plan.bfvVerifierRoutes;
    const first = plan.bfvVerifierRoutes[0];
    deployment.dkgAggregatorVerifier = first.dkgAggregatorVerifier;
    deployment.decryptionAggregatorVerifier =
      first.decryptionAggregatorVerifier;
    deployment.verifierZkTranscriptLib = first.verifierZkTranscriptLib;
    deployment.dkgVerifierRelationsLib = first.dkgVerifierRelationsLib;
    deployment.decryptionVerifierRelationsLib =
      first.decryptionVerifierRelationsLib;
    writeJson(deploymentPath(config), deployment);
    writeDeployedContracts(networkName(), plan);
  }

  console.log(`
v0.19 cutover validated
  Interfold implementation: ${plan.interfoldImplementation}
  registry implementation:  ${plan.registryImplementation}
  BFV routes:               ${plan.bfvVerifierRoutes.length}
  CRISP program:            ${plan.crispProgram}
  node release:             protocol ${plan.nodeRelease.protocolVersion}, generation ${plan.nodeRelease.nodeGeneration}
  requests:                 ${paused ? "paused" : "open"}
  deployment records:       ${hasFlag("write-records") ? "updated" : "unchanged (pass --write-records to update them)"}
`);
  return plan;
}

/**
 * Record the cutover's contracts in `deployed_contracts.json`, which the release manifest is built
 * from. The OpenVM verifiers come from the CRISP record and replace the RISC Zero one; a contract
 * that `prepare` deployed gets the block before which none of them existed.
 */
function writeDeployedContracts(network: string, plan: V19CutoverPlan): void {
  const file = path.resolve(protocolDir, "..", "..", "deployed_contracts.json");
  type ContractRecord = {
    address?: string;
    blockNumber?: number;
    [field: string]: unknown;
  };
  const records = fs.existsSync(file)
    ? readJson<{ [network: string]: { [name: string]: ContractRecord } }>(file)
    : {};
  const chain = (records[network] ??= {});
  const deployed = (address: string): ContractRecord =>
    plan.deployFromBlock === undefined
      ? { address }
      : { address, blockNumber: plan.deployFromBlock };
  const interfold = chain.Interfold as
    | { proxyRecords?: { implementationAddress?: string }; libraries?: unknown }
    | undefined;
  if (interfold?.proxyRecords) {
    interfold.proxyRecords.implementationAddress = plan.interfoldImplementation;
    interfold.libraries = {
      InterfoldLifecycle: plan.lifecycleLibrary,
      InterfoldPricing: plan.pricingLibrary,
    };
  }
  const registry = chain.CiphernodeRegistryOwnable as
    | {
        proxyRecords?: { implementationAddress?: string };
        libraries?: Record<string, string>;
      }
    | undefined;
  if (registry?.proxyRecords) {
    registry.proxyRecords.implementationAddress = plan.registryImplementation;
    registry.libraries = {
      ...registry.libraries,
      RegistrySortitionLib: plan.registrySortitionLibrary,
      DkgPublicationLib: plan.dkgPublicationLibrary,
    };
  }
  chain.RegistrySortitionLib = deployed(plan.registrySortitionLibrary);
  chain.DkgPublicationLib = deployed(plan.dkgPublicationLibrary);
  chain.InterfoldLifecycle = deployed(plan.lifecycleLibrary);
  chain.InterfoldPricing = deployed(plan.pricingLibrary);
  chain.BfvPkVerifierRouter = deployed(plan.pkVerifier);
  chain.BfvDecryptionVerifierRouter = deployed(plan.decryptionVerifier);
  const crisp = readCrispRecord(network);
  for (const name of ["OpenVmBfvCiphertextVerifier", "OpenVmReceiptVerifier"]) {
    if (crisp[name]?.address) chain[name] = crisp[name];
  }
  delete chain.Risc0BfvCiphertextVerifier;
  writeJson(file, records);
}

export async function prepareV19Resume(): Promise<void> {
  if (!hasFlag("ciphernodes-restarted")) {
    throw new Error(
      "Restart every ciphernode on the planned release, confirm that the processes are online, and pass --ciphernodes-restarted",
    );
  }
  const plan = await validateV19Cutover();
  const { ethers } = await connect();
  const { config, deployment } = loadContext();
  const interfold = await ethers.getContractAt(
    "Interfold",
    deployment.interfold,
  );
  if (!(await interfold.requestsPaused())) {
    throw new Error("Requests are already open");
  }
  const bonding = await ethers.getContractAt(
    "BondingRegistry",
    deployment.bondingRegistryProxy,
  );
  const requiredActive = requiredActiveOperators(
    config.interfold.committeeThresholds,
    config.chainId,
    arg("sepolia-committee-size"),
  );
  const active = await bonding.numActiveOperators();
  if (active < requiredActive) {
    throw new Error(
      `Only ${active} release-ready operators are active; ${requiredActive} are required by the largest committee`,
    );
  }
  await assertRefreshedOwnerCapacity(bonding, requiredActive).catch((error) => {
    throw new Error(
      `${(error as Error).message} \`v19Cutover.ts refresh\` refreshes the remaining operators.`,
    );
  });

  const txs = [
    safeTx(
      deployment.interfold,
      interfoldInterface.encodeFunctionData("setRequestsPaused", [false]),
    ),
  ];
  const rawBatchFile = batchPath(config, "resume");
  const batch = governanceBatch(config, txs);
  batch.meta.name = `${config.name} v0.19 resume`;
  batch.meta.description =
    "Resume E3 requests after the v0.19 cutover was validated and enough operators run the release.";
  writeJson(rawBatchFile, batch);
  let safeBuilderFile: string | undefined;
  if (config.governance) {
    safeBuilderFile = governanceSafeBuilderPath({
      ...config,
      name: `${config.name}.v19-resume`,
    });
    const safeBatch = aragonAdminSafeBatch(config, txs);
    safeBatch.meta.name = batch.meta.name;
    safeBatch.meta.description = batch.meta.description;
    writeJson(safeBuilderFile, safeBatch);
  }
  if (hasFlag("propose-safe")) {
    await proposeSafeBatch(
      config,
      config.governance ? aragonAdminSafeTransactions(config, txs) : txs,
      config.governance?.proposerSafe ?? config.safe,
    );
  }
  console.log(`
v0.19 resume prepared
  node release:       ${plan.nodeRelease.version} (protocol ${plan.nodeRelease.protocolVersion})
  active operators:   ${active}/${requiredActive}
  governance batch:   ${repoRelativePath(rawBatchFile)}
  Aragon Safe batch:  ${safeBuilderFile ? repoRelativePath(safeBuilderFile) : "not configured"}
`);
}

const LOG_WINDOW = 2_000;
const REFRESH_BATCH = 20;
const CIPHERNODE_ADDED = ethersLib.id(
  "CiphernodeAdded(address,uint256,uint256,uint256)",
);

/** The registry's deploy block in `deployed_contracts.json`, where the operator history starts. */
export function registryDeployBlock(network: string): number | undefined {
  const file = path.resolve(protocolDir, "..", "..", "deployed_contracts.json");
  if (!fs.existsSync(file)) return undefined;
  const records =
    readJson<Record<string, Record<string, { blockNumber?: number }>>>(file);
  const block = records[network]?.CiphernodeRegistryOwnable?.blockNumber;
  return typeof block === "number" ? block : undefined;
}

/**
 * Every operator that the registry added from `fromBlock` to `toBlock`: registration adds each
 * operator, and the registry keeps no list. A window that fails is read again from the next
 * provider.
 */
export async function addedOperators(
  providers: ethersLib.Provider[],
  registry: string,
  fromBlock: number,
  toBlock: number,
): Promise<string[]> {
  const operators = new Set<string>();
  for (let start = fromBlock; start <= toBlock; start += LOG_WINDOW) {
    const end = Math.min(start + LOG_WINDOW - 1, toBlock);
    for (let attempt = 1; ; attempt += 1) {
      try {
        const logs = await providers[(attempt - 1) % providers.length].getLogs({
          address: registry,
          topics: [CIPHERNODE_ADDED],
          fromBlock: start,
          toBlock: end,
        });
        for (const log of logs) {
          operators.add(
            ethersLib.getAddress(ethersLib.dataSlice(log.topics[1], 12)),
          );
        }
        break;
      } catch (error) {
        if (attempt >= 3 * providers.length) throw error;
        await new Promise((resolve) => setTimeout(resolve, 1000 * attempt));
      }
    }
  }
  return [...operators];
}

export async function refreshV19Operators(): Promise<void> {
  const { ethers } = await connect();
  const { config, deployment } = loadContext();
  await requireSupportedChain(ethers, config, deployment);
  const [sender] = await ethers.getSigners();
  const bonding = await ethers.getContractAt(
    "BondingRegistry",
    deployment.bondingRegistryProxy,
    sender,
  );
  const fromBlock = Number(
    arg("from-block") ?? registryDeployBlock(networkName()) ?? 0,
  );
  const logProviders = (arg("log-rpc") ?? "")
    .split(",")
    .map((url) => url.trim())
    .filter(Boolean)
    .map((url) => new ethersLib.JsonRpcProvider(url));
  const added = await addedOperators(
    logProviders.length > 0 ? logProviders : [ethers.provider],
    deployment.ciphernodeRegistry,
    fromBlock,
    await ethers.provider.getBlockNumber(),
  );
  const registered: string[] = [];
  for (const operator of added) {
    if (await bonding.isRegistered(operator)) registered.push(operator);
  }
  const expected = await bonding.numRegisteredOperators();
  if (BigInt(registered.length) !== expected) {
    throw new Error(
      `The registry history from block ${fromBlock} names ${registered.length} of ${expected} registered operators; pass an earlier --from-block or a --log-rpc with the full history`,
    );
  }
  // An active operator was refreshed under the current rules, by its acknowledgment or by a
  // refresh. Refreshing the others again is harmless.
  const stale: string[] = [];
  for (const operator of registered) {
    if (!(await bonding.isActive(operator))) stale.push(operator);
  }
  for (let start = 0; start < stale.length; start += REFRESH_BATCH) {
    const batch = stale.slice(start, start + REFRESH_BATCH);
    // The estimate runs at the latest block's timestamp, where a checkpoint written in that block
    // is overwritten; the transaction lands later and appends one, which costs more.
    const gas = await bonding.refreshOperatorStatuses.estimateGas(batch);
    await (
      await bonding.refreshOperatorStatuses(batch, { gasLimit: gas * 2n })
    ).wait();
  }
  console.log(`
v0.19 operator statuses refreshed
  registered operators: ${registered.length}
  refreshed now:        ${stale.length}
  active operators:     ${await bonding.numActiveOperators()}
  resume after the next block, once the refresh is in the past
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
        ["prepare", "validate", "refresh", "resume"].includes(value),
    );
  const run =
    action === "validate"
      ? validateV19Cutover
      : action === "refresh"
        ? refreshV19Operators
        : action === "resume"
          ? prepareV19Resume
          : action === "prepare"
            ? prepareV19Cutover
            : undefined;
  if (!run) {
    console.error(
      "Usage: v19Cutover.ts prepare|validate|refresh|resume [options]",
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
