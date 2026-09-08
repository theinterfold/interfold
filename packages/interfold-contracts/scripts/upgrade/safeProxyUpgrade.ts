// SPDX-License-Identifier: LGPL-3.0-only
import { ethers as ethersLib } from "ethers";
import path from "path";

import { CiphernodeRegistryOwnable__factory as RegistryFactory } from "../../types";
import { connect, hasFlag } from "../protocol/cli";
import { proxyAdminInterface } from "../protocol/constants";
import {
  deploymentPath,
  protocolDir,
  readJson,
  repoRelativePath,
  writeJson,
} from "../protocol/files";
import { governanceBatch, proposeSafeBatch, safeTx } from "../protocol/safe";
import type {
  ProtocolConfigFile,
  ProtocolDeployment,
  SafeProposal,
  SafeTransaction,
} from "../protocol/types";
import {
  deployedAddress,
  loadConfig,
  requireContract,
} from "../protocol/values";

const IMPLEMENTATION_SLOT =
  "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";

export async function proxyImplementation(
  ethers: any,
  proxy: string,
): Promise<string> {
  const word = await ethers.provider.getStorage(proxy, IMPLEMENTATION_SLOT);
  return ethersLib.getAddress(`0x${word.slice(-40)}`);
}

export type UpgradeTarget =
  | "bondingRegistry"
  | "ciphernodeRegistry"
  | "interfold"
  | "e3RefundManager";

interface BondedVotingDeployment {
  bondedCheckpoints: string;
  bondedVotes: string;
  resyncOwners: string[];
}

interface UpgradePlan {
  name: string;
  target: UpgradeTarget;
  bondedCheckpoints?: string;
  bondedVotes?: string;
  bondedResyncOwners?: string[];
  proxy: string;
  proxyAdmin: string;
  implementation: string;
  assetLibrary?: string;
  eligibilityLibrary?: string;
  slashingLibrary?: string;
  registrationLibrary?: string;
  ownershipLibrary?: string;
  lifecycleLibrary?: string;
  pricingLibrary?: string;
  sortitionLibrary?: string;
  operator: string;
  protocolOwner: string;
  safe?: string;
  safeTransactions: string;
  safeProposal?: SafeProposal;
}

export async function proposeProxyUpgrade(
  target: UpgradeTarget,
): Promise<void> {
  const { ethers } = await connect();
  const config = loadConfig();
  const deployment = readJson<ProtocolDeployment>(deploymentPath(config));
  const network = await ethers.provider.getNetwork();
  if (Number(network.chainId) !== deployment.chainId) {
    throw new Error("Connected to the wrong network for this deployment file");
  }

  const [operator] = await ethers.getSigners();
  const operatorAddress = await operator.getAddress();
  const deployed = await deployUpgradeImplementation(
    ethers,
    operator,
    target,
    deployment,
  );
  const proxy = proxyFor(target, config, deployment);
  const proxyAdmin = proxyAdminFor(target, config, deployment);

  await requireContract(ethers.provider, proxy, `${target} proxy`);
  await requireContract(ethers.provider, proxyAdmin, `${target} ProxyAdmin`);
  const admin = await ethers.getContractAt("ProxyAdmin", proxyAdmin);
  const adminOwner = await admin.owner();
  if (adminOwner.toLowerCase() !== config.protocolOwner.toLowerCase()) {
    throw new Error(
      `${target} ProxyAdmin owner mismatch: expected ${config.protocolOwner}, got ${adminOwner}`,
    );
  }

  const txs = [
    safeTx(
      proxyAdmin,
      proxyAdminInterface.encodeFunctionData("upgradeAndCall", [
        proxy,
        deployed.implementation,
        "0x",
      ]),
    ),
  ];

  let bonded: BondedVotingDeployment | undefined;
  if (target === "bondingRegistry") {
    bonded = await appendBondedVotingTxs(ethers, config, proxy, txs);
  }

  const batchFile = upgradeBatchPath(config, target);
  const batch = governanceBatch(config, txs);
  batch.meta.name = `${config.name} ${target} upgrade`;
  batch.meta.description = `Upgrade ${target} implementation through its Safe-owned ProxyAdmin.`;
  writeJson(batchFile, batch);

  const plan: UpgradePlan = {
    name: config.name,
    target,
    proxy,
    proxyAdmin,
    implementation: deployed.implementation,
    bondedCheckpoints: bonded?.bondedCheckpoints,
    bondedVotes: bonded?.bondedVotes,
    bondedResyncOwners: bonded?.resyncOwners,
    assetLibrary: deployed.assetLibrary,
    eligibilityLibrary: deployed.eligibilityLibrary,
    slashingLibrary: deployed.slashingLibrary,
    registrationLibrary: deployed.registrationLibrary,
    ownershipLibrary: deployed.ownershipLibrary,
    lifecycleLibrary: deployed.lifecycleLibrary,
    pricingLibrary: deployed.pricingLibrary,
    sortitionLibrary: deployed.sortitionLibrary,
    operator: operatorAddress,
    protocolOwner: config.protocolOwner,
    safe: config.safe,
    safeTransactions: repoRelativePath(batchFile),
  };

  if (hasFlag("propose-safe")) {
    plan.safeProposal = await proposeSafeBatch(config, txs);
  }
  writeJson(upgradePlanPath(config, target), plan);

  printPlan(plan, txs);
}

/**
 * Read the attached bonded history, tolerating an implementation that predates the getter.
 *
 * This reads the proxy while it still runs the *old* implementation, which is the one this upgrade
 * replaces. Every deployment that needs the upgrade is therefore on a build with no
 * `bondedCheckpoints()`, where the call finds no matching selector and a plain typed read throws —
 * aborting the script before it writes the batch, on exactly the deployments this exists to serve.
 *
 * A missing selector means nothing is attached yet. Transport failures stay fatal: reading one as
 * "unattached" would queue a second `setBondedCheckpoints` that the one-shot setter rejects, and
 * the whole governance batch would revert on execution.
 *
 * The two cases are told apart by re-reading the proxy's code rather than by matching an error
 * code: providers disagree on what they attach to a missing selector — Hardhat's in-process
 * provider reports no code at all — so matching on one silently stops working against another. A
 * successful second read proves the transport is healthy, which leaves the missing selector as the
 * only explanation. A failing one rethrows and stays fatal.
 */
async function readAttachedCheckpoints(
  ethers: any,
  registry: any,
  proxy: string,
): Promise<string> {
  try {
    return await registry.bondedCheckpoints();
  } catch (readError) {
    let code: string;
    try {
      code = await ethers.provider.getCode(proxy);
    } catch {
      throw readError;
    }
    // `proposeProxyUpgrade` already required code here, so an empty result means the chain moved
    // under the script rather than that the getter is missing.
    if (code === "0x") throw readError;
    return ethersLib.ZeroAddress;
  }
}

/**
 * Attach the bonded-voting contracts, unless the registry already has a history attached.
 *
 * The upgrade alone does not enable bonded voting: the sync is a no-op while unconfigured, so
 * without this every operator keeps reading as zero bonded voting power. The transactions go after
 * the upgrade in the batch, because the function they call only exists on the new implementation.
 *
 * Skipped when a history is already attached, so re-running the upgrade neither redeploys the
 * contracts nor queues a call the one-shot setter would reject.
 */
async function appendBondedVotingTxs(
  ethers: any,
  config: ProtocolConfigFile,
  proxy: string,
  txs: SafeTransaction[],
): Promise<BondedVotingDeployment | undefined> {
  const registry = await ethers.getContractAt("BondingRegistry", proxy);
  const attached = await readAttachedCheckpoints(ethers, registry, proxy);
  if (attached !== ethersLib.ZeroAddress) {
    console.log(`  bonded history already attached at ${attached}`);
    return undefined;
  }

  // Bound to the proxy: that is the address that calls `sync`.
  const checkpointsFactory =
    await ethers.getContractFactory("BondedCheckpoints");
  const checkpoints = await checkpointsFactory.deploy(proxy);
  await checkpoints.waitForDeployment();
  const bondedCheckpoints = await deployedAddress(checkpoints);

  const votesFactory = await ethers.getContractFactory("BondedVotes");
  const votes = await votesFactory.deploy(
    config.fold,
    config.escrowVotesAdapter ?? config.fold,
    bondedCheckpoints,
  );
  await votes.waitForDeployment();
  const bondedVotes = await deployedAddress(votes);

  txs.push(
    safeTx(
      proxy,
      registry.interface.encodeFunctionData("setBondedCheckpoints", [
        bondedCheckpoints,
      ]),
    ),
  );

  // Attaching does not backfill, so owners that bonded before this upgrade would read as zero
  // until their next mutation. `resyncBondedCheckpoint` is permissionless and idempotent — it can
  // only write the owner's true current total — so it is safe to batch here.
  const resyncOwners = config.bondedResyncOwners ?? [];
  for (const owner of resyncOwners) {
    txs.push(
      safeTx(
        proxy,
        registry.interface.encodeFunctionData("resyncBondedCheckpoint", [
          owner,
        ]),
      ),
    );
  }

  return { bondedCheckpoints, bondedVotes, resyncOwners };
}

export async function deployUpgradeImplementation(
  ethers: any,
  operator: any,
  target: UpgradeTarget,
  deployment: ProtocolDeployment,
): Promise<{
  implementation: string;
  assetLibrary?: string;
  eligibilityLibrary?: string;
  slashingLibrary?: string;
  registrationLibrary?: string;
  ownershipLibrary?: string;
  lifecycleLibrary?: string;
  pricingLibrary?: string;
  sortitionLibrary?: string;
}> {
  if (target === "interfold") {
    const pricingFactory = await ethers.getContractFactory("InterfoldPricing");
    const pricing = await pricingFactory.deploy();
    await pricing.waitForDeployment();
    const pricingLibrary = await deployedAddress(pricing);

    const lifecycleFactory =
      await ethers.getContractFactory("InterfoldLifecycle");
    const lifecycle = await lifecycleFactory.deploy();
    await lifecycle.waitForDeployment();
    const lifecycleLibrary = await deployedAddress(lifecycle);

    const factory = await ethers.getContractFactory("Interfold", {
      libraries: {
        InterfoldLifecycle: lifecycleLibrary,
        InterfoldPricing: pricingLibrary,
      },
    });
    const implementation = await factory.deploy();
    await implementation.waitForDeployment();
    return {
      implementation: await deployedAddress(implementation),
      lifecycleLibrary,
      pricingLibrary,
    };
  }

  if (target === "ciphernodeRegistry") {
    const sortitionFactory = await ethers.getContractFactory(
      "RegistrySortitionLib",
    );
    const sortition = await sortitionFactory.deploy();
    await sortition.waitForDeployment();
    const sortitionLibrary = await deployedAddress(sortition);
    const factory = await ethers.getContractFactory(
      RegistryFactory.abi,
      RegistryFactory.linkBytecode({
        "npm/poseidon-solidity@0.0.5/PoseidonT3.sol:PoseidonT3":
          deployment.poseidonT3,
        "project/contracts/lib/RegistrySortitionLib.sol:RegistrySortitionLib":
          sortitionLibrary,
      }),
      operator,
    );
    const implementation = await factory.deploy();
    await implementation.waitForDeployment();
    return {
      implementation: await deployedAddress(implementation),
      sortitionLibrary,
    };
  }

  if (target === "bondingRegistry") {
    const assetFactory = await ethers.getContractFactory("BondingAssetLib");
    const asset = await assetFactory.deploy();
    await asset.waitForDeployment();
    const assetLibrary = await deployedAddress(asset);

    const eligibilityFactory = await ethers.getContractFactory(
      "BondingEligibilityLib",
    );
    const eligibility = await eligibilityFactory.deploy();
    await eligibility.waitForDeployment();
    const eligibilityLibrary = await deployedAddress(eligibility);

    const slashingFactory =
      await ethers.getContractFactory("BondingSlashingLib");
    const slashing = await slashingFactory.deploy();
    await slashing.waitForDeployment();
    const slashingLibrary = await deployedAddress(slashing);

    const registrationFactory = await ethers.getContractFactory(
      "BondingRegistrationLib",
    );
    const registration = await registrationFactory.deploy();
    await registration.waitForDeployment();
    const registrationLibrary = await deployedAddress(registration);

    const ownershipFactory = await ethers.getContractFactory(
      "BondingOwnershipLib",
    );
    const ownership = await ownershipFactory.deploy();
    await ownership.waitForDeployment();
    const ownershipLibrary = await deployedAddress(ownership);

    const factory = await ethers.getContractFactory("BondingRegistry", {
      libraries: {
        BondingAssetLib: assetLibrary,
        BondingEligibilityLib: eligibilityLibrary,
        BondingSlashingLib: slashingLibrary,
        BondingRegistrationLib: registrationLibrary,
        BondingOwnershipLib: ownershipLibrary,
      },
    });
    const implementation = await factory.deploy();
    await implementation.waitForDeployment();
    return {
      implementation: await deployedAddress(implementation),
      assetLibrary,
      eligibilityLibrary,
      slashingLibrary,
      registrationLibrary,
      ownershipLibrary,
    };
  }

  const factory = await ethers.getContractFactory("E3RefundManager");
  const implementation = await factory.deploy();
  await implementation.waitForDeployment();
  return { implementation: await deployedAddress(implementation) };
}

function proxyFor(
  target: UpgradeTarget,
  config: ProtocolConfigFile,
  deployment: ProtocolDeployment,
): string {
  if (target === "bondingRegistry") return config.bondingRegistryProxy;
  if (target === "ciphernodeRegistry") return deployment.ciphernodeRegistry;
  if (target === "interfold") return deployment.interfold;
  return deployment.e3RefundManager;
}

function proxyAdminFor(
  target: UpgradeTarget,
  config: ProtocolConfigFile,
  deployment: ProtocolDeployment,
): string {
  if (target === "bondingRegistry") return config.bondingRegistryProxyAdmin;
  if (target === "ciphernodeRegistry")
    return deployment.ciphernodeRegistryProxyAdmin;
  if (target === "interfold") return deployment.interfoldProxyAdmin;
  return deployment.e3RefundManagerProxyAdmin;
}

function upgradeBatchPath(
  config: ProtocolConfigFile,
  target: UpgradeTarget,
): string {
  return path.join(protocolDir, `${config.name}.${target}.upgrade.safe.json`);
}

function upgradePlanPath(
  config: ProtocolConfigFile,
  target: UpgradeTarget,
): string {
  return path.join(protocolDir, `${config.name}.${target}.upgrade.json`);
}

function printPlan(plan: UpgradePlan, txs: SafeTransaction[]): void {
  console.log(`
Protocol upgrade prepared
  target:          ${plan.target}
  proxy:           ${plan.proxy}
  proxyAdmin:      ${plan.proxyAdmin}
  implementation:  ${plan.implementation}
  bondedCheckpoints: ${plan.bondedCheckpoints ?? "(not applicable)"}
  bondedVotes:     ${plan.bondedVotes ?? "(not applicable)"}
  bonded resyncs:  ${plan.bondedResyncOwners?.length ?? 0}
  assetLibrary:    ${plan.assetLibrary ?? "(not applicable)"}
  eligibilityLibrary: ${plan.eligibilityLibrary ?? "(not applicable)"}
  slashingLibrary: ${plan.slashingLibrary ?? "(not applicable)"}
  registrationLibrary: ${plan.registrationLibrary ?? "(not applicable)"}
  ownershipLibrary: ${plan.ownershipLibrary ?? "(not applicable)"}
  lifecycleLibrary: ${plan.lifecycleLibrary ?? "(not applicable)"}
  pricingLibrary:  ${plan.pricingLibrary ?? "(not applicable)"}
  sortitionLibrary: ${plan.sortitionLibrary ?? "(not applicable)"}
  operator:        ${plan.operator}
  protocol owner:  ${plan.protocolOwner}
  governance batch:${plan.safeTransactions}
  txs:             ${txs.length}
  proposal:        ${plan.safeProposal?.url ?? "(not proposed)"}
`);
}
