// SPDX-License-Identifier: LGPL-3.0-only
import { ethers as ethersLib } from "ethers";
import fs from "fs";

import { syncProtocolDeploymentRecords } from "../deploymentRecords";
import { arg, connect, hasFlag, networkName } from "./cli";
import { proxyAdminInterface } from "./constants";
import { deployProtocolContracts } from "./deployContracts";
import {
  deploymentPath,
  governanceSafeBuilderPath,
  readJson,
  repoRelativePath,
  safeBatchPath,
  writeJson,
} from "./files";
import { assertVrfSubscription, requireRandomnessConfig } from "./randomness";
import {
  aragonAdminSafeBatch,
  aragonAdminSafeTransactions,
  governanceBatch,
  proposeSafeBatch,
} from "./safe";
import { buildSafeTransactions } from "./transactions";
import type { ProtocolDeployment, SafeTransaction } from "./types";
import { address, loadConfig, requireContract } from "./values";

const DIRECT_GOVERNANCE_CHAIN_IDS = new Set([31337, 11155111]);

async function assertAragonGovernancePreconditions(
  ethers: any,
  config: ReturnType<typeof loadConfig>,
) {
  if (!config.governance) return;

  await Promise.all([
    requireContract(
      ethers.provider,
      config.governance.adminPlugin,
      "governance.adminPlugin",
    ),
    requireContract(
      ethers.provider,
      config.governance.proposerSafe,
      "governance.proposerSafe",
    ),
  ]);

  const adminPlugin = new ethersLib.Contract(
    config.governance.adminPlugin,
    [
      "function dao() view returns (address)",
      "function getTargetConfig() view returns (tuple(address target,uint8 operation))",
      "function EXECUTE_PROPOSAL_PERMISSION_ID() view returns (bytes32)",
    ],
    ethers.provider,
  );
  const dao = new ethersLib.Contract(
    config.protocolOwner,
    [
      "function hasPermission(address where,address who,bytes32 permissionId,bytes data) view returns (bool)",
    ],
    ethers.provider,
  );

  const daoAddress = address(await adminPlugin.dao(), "governance.dao");
  if (daoAddress !== config.protocolOwner) {
    throw new Error(
      `Aragon Admin plugin DAO mismatch: expected ${config.protocolOwner}, got ${daoAddress}`,
    );
  }

  const targetConfig = await adminPlugin.getTargetConfig();
  const target = address(targetConfig.target, "governance.target");
  const operation = Number(targetConfig.operation);
  if (target !== config.protocolOwner || operation !== 0) {
    throw new Error(
      `Aragon Admin plugin target mismatch: expected (${config.protocolOwner}, 0), got (${target}, ${operation})`,
    );
  }

  const executeProposalPermission =
    await adminPlugin.EXECUTE_PROPOSAL_PERMISSION_ID();
  const proposerCanExecute = await dao.hasPermission(
    config.governance.adminPlugin,
    config.governance.proposerSafe,
    executeProposalPermission,
    "0x",
  );
  if (!proposerCanExecute) {
    throw new Error(
      `governance.proposerSafe cannot execute proposals through ${config.governance.adminPlugin}`,
    );
  }

  const pluginCanExecute = await dao.hasPermission(
    config.protocolOwner,
    config.governance.adminPlugin,
    ethersLib.id("EXECUTE_PERMISSION"),
    "0x",
  );
  if (!pluginCanExecute) {
    throw new Error(
      `Aragon Admin plugin cannot execute through DAO ${config.protocolOwner}`,
    );
  }
}

async function assertPreconditions(
  ethers: any,
  config: ReturnType<typeof loadConfig>,
) {
  const randomness = requireRandomnessConfig(config);
  const contracts = [
    requireContract(ethers.provider, config.fold, "fold"),
    requireContract(ethers.provider, config.feeToken, "feeToken"),
    requireContract(
      ethers.provider,
      config.ticketUnderlyingToken,
      "ticketUnderlyingToken",
    ),
    requireContract(
      ethers.provider,
      config.bondingRegistryProxy,
      "bondingRegistryProxy",
    ),
    requireContract(
      ethers.provider,
      config.bondingRegistryProxyAdmin,
      "bondingRegistryProxyAdmin",
    ),
    requireContract(
      ethers.provider,
      randomness.coordinator,
      "randomness.coordinator",
    ),
  ];
  if (config.escrowVotesAdapter) {
    contracts.push(
      requireContract(
        ethers.provider,
        config.escrowVotesAdapter,
        "escrowVotesAdapter",
      ),
    );
  }
  if (!config.deployMockE3Program) {
    contracts.push(
      requireContract(ethers.provider, config.e3Programs[0], "e3Programs[0]"),
    );
  }
  await Promise.all(contracts);

  if (config.safe) {
    await requireContract(ethers.provider, config.safe, "safe");
  }
  if (config.ciphertextVerifier) {
    await requireContract(
      ethers.provider,
      config.ciphertextVerifier,
      "ciphertextVerifier",
    );
  }
  if (config.bindInitialE3Program) {
    const program = new ethersLib.Contract(
      config.e3Programs[0],
      ["function owner() view returns (address)"],
      ethers.provider,
    );
    const programOwner = address(await program.owner(), "e3Programs[0].owner");
    if (programOwner !== config.protocolOwner) {
      throw new Error(
        `E3 Program owner mismatch: expected ${config.protocolOwner}, got ${programOwner}`,
      );
    }
  }
  if (!config.verifiers?.deploy) {
    for (const [label, target] of [
      ["decryptionVerifier", config.verifiers?.decryptionVerifier],
      ["pkVerifier", config.verifiers?.pkVerifier],
      [
        "dkgFoldAttestationVerifier",
        config.verifiers?.dkgFoldAttestationVerifier,
      ],
    ] as const) {
      if (target) await requireContract(ethers.provider, target, label);
    }
  }

  const proxyAdmin = new ethersLib.Contract(
    config.bondingRegistryProxyAdmin,
    proxyAdminInterface,
    ethers.provider,
  );
  const proxyAdminOwner = address(await proxyAdmin.owner(), "proxyAdmin.owner");
  if (proxyAdminOwner !== config.protocolOwner) {
    throw new Error(
      `BondingRegistry ProxyAdmin owner mismatch: expected ${config.protocolOwner}, got ${proxyAdminOwner}`,
    );
  }
  await assertVrfSubscription(ethers, config);
  await assertAragonGovernancePreconditions(ethers, config);
}

export async function actionDeploy(): Promise<void> {
  const { ethers } = await connect();
  const network = await ethers.provider.getNetwork();
  const chainId = Number(network.chainId);
  const config = loadConfig();
  if (chainId !== config.chainId) {
    throw new Error(
      `Connected chainId ${chainId} != config.chainId ${config.chainId}`,
    );
  }

  const [operator] = await ethers.getSigners();
  const operatorAddress = await operator.getAddress();
  await assertPreconditions(ethers, config);

  console.log(`Deploying protocol contracts for ${config.name}`);

  const result = await deployProtocolContracts(ethers, operator, config);
  const blockNumber = await ethers.provider.getBlockNumber();
  const txs = buildSafeTransactions(
    config,
    result.contracts,
    result.interfaces,
  );
  const batchFile = safeBatchPath(config);
  writeJson(batchFile, governanceBatch(config, txs));
  const governanceSafeBuilderFile = config.governance
    ? governanceSafeBuilderPath(config)
    : undefined;
  if (governanceSafeBuilderFile) {
    writeJson(governanceSafeBuilderFile, aragonAdminSafeBatch(config, txs));
  }

  const deployment: ProtocolDeployment = {
    name: config.name,
    chainId,
    operator: operatorAddress,
    protocolOwner: config.protocolOwner,
    safe: config.safe,
    fold: config.fold,
    feeToken: config.feeToken,
    ticketUnderlyingToken: config.ticketUnderlyingToken,
    randomness: config.randomness ? { ...config.randomness } : undefined,
    bondingRegistryProxy: config.bondingRegistryProxy,
    bondingRegistryProxyAdmin: config.bondingRegistryProxyAdmin,
    ...result.contracts,
    safeTransactions: repoRelativePath(batchFile),
    governanceSafeBuilder: governanceSafeBuilderFile
      ? repoRelativePath(governanceSafeBuilderFile)
      : undefined,
  };
  const deploymentFile = deploymentPath(config);
  writeJson(deploymentFile, deployment);
  syncProtocolDeploymentRecords(config, deployment, result.interfaces, {
    chain: networkName(),
    blockNumber,
    syncIntegrationConfig: hasFlag("sync-integration-config"),
  });

  if (hasFlag("propose-safe")) {
    const proposalTransactions = config.governance
      ? aragonAdminSafeTransactions(config, txs)
      : txs;
    deployment.safeProposal = await proposeSafeBatch(
      config,
      proposalTransactions,
      config.governance?.proposerSafe ?? config.safe,
    );
    writeJson(deploymentFile, deployment);
    printProposal(deployment.safeProposal);
  }

  console.log(`
Protocol contracts deployed
  fee token:              ${deployment.feeToken}
  ticket underlying:      ${deployment.ticketUnderlyingToken}
  ticketToken:            ${deployment.ticketToken}
  slashingManager:        ${deployment.slashingManager}
  slashingEvidenceLib:    ${deployment.slashingEvidenceLib}
  ciphernodeRegistry:     ${deployment.ciphernodeRegistry}
  interfold:              ${deployment.interfold}
  initialE3Program:       ${deployment.initialE3Program}
  ciphertextVerifier:     ${deployment.ciphertextVerifier ?? config.ciphertextVerifier ?? "(not configured)"}
  interfoldLifecycle:     ${deployment.interfoldLifecycle}
  interfoldPricing:       ${deployment.interfoldPricing}
  e3RefundManager:        ${deployment.e3RefundManager}
  bondingAssetLib:        ${deployment.bondingAssetLib}
  bondingEligibilityLib:  ${deployment.bondingEligibilityLib}
  bondingSlashingLib:     ${deployment.bondingSlashingLib}
  bonding implementation: ${deployment.bondingRegistryImplementation}
  nodeReleaseRegistry:     ${deployment.nodeReleaseRegistry}
  bondedCheckpoints:      ${deployment.bondedCheckpoints}
  bondedVotes:            (run --action activate-voting after the governance batch)

Governance batch required
  file: ${batchFile}
  txs:  ${txs.length}
${
  governanceSafeBuilderFile
    ? `
Safe Builder wrapper
  file: ${governanceSafeBuilderFile}
  safe: ${config.governance!.proposerSafe}
  txs:  1 (${txs.length} DAO actions)
`
    : ""
}

Deployment file
  ${deploymentFile}
`);
}

export async function actionCheckConfig(): Promise<void> {
  const { ethers } = await connect();
  const network = await ethers.provider.getNetwork();
  const chainId = Number(network.chainId);
  const config = loadConfig();
  if (chainId !== config.chainId) {
    throw new Error(
      `Connected chainId ${chainId} != config.chainId ${config.chainId}`,
    );
  }
  await assertPreconditions(ethers, config);
  console.log(`
Protocol configuration is valid
  name:                 ${config.name}
  chainId:              ${config.chainId}
  protocol owner:       ${config.protocolOwner}
  FOLD:                 ${config.fold}
  escrow votes adapter: ${config.escrowVotesAdapter ?? "(not configured)"}
  fee token:            ${config.feeToken}
  ticket underlying:    ${config.ticketUnderlyingToken}
  BondingRegistry:      ${config.bondingRegistryProxy}
  ProxyAdmin:           ${config.bondingRegistryProxyAdmin}
  initial E3 program:   ${
    config.deployMockE3Program
      ? "MockE3Program (deployed with protocol)"
      : config.e3Programs[0]
  }
  ciphertext verifier:  ${
    config.deployMockCiphertextVerifier
      ? "DeployableMockCiphertextVerifier (deployed with protocol)"
      : (config.ciphertextVerifier ?? "(not configured)")
  }
  Aragon Admin plugin:  ${config.governance?.adminPlugin ?? "(not configured)"}
  proposer Safe:        ${config.governance?.proposerSafe ?? "(not configured)"}
`);
}

export async function actionProposeSafe(): Promise<void> {
  const config = loadConfig();
  const transactions = readGovernanceBatch(config);
  const proposalTransactions = config.governance
    ? aragonAdminSafeTransactions(config, transactions)
    : transactions;
  const proposal = await proposeSafeBatch(
    config,
    proposalTransactions,
    config.governance?.proposerSafe ?? config.safe,
  );

  if (fs.existsSync(deploymentPath(config))) {
    const deployment = readJson<ProtocolDeployment>(deploymentPath(config));
    deployment.safeProposal = proposal;
    writeJson(deploymentPath(config), deployment);
  }

  printProposal(proposal);
}

export async function actionExecuteGovernance(): Promise<void> {
  const { ethers } = await connect();
  const config = loadConfig();
  const network = await ethers.provider.getNetwork();
  const chainId = Number(network.chainId);
  if (chainId !== config.chainId) {
    throw new Error(
      `Connected chainId ${chainId} != config.chainId ${config.chainId}`,
    );
  }
  if (!DIRECT_GOVERNANCE_CHAIN_IDS.has(chainId)) {
    throw new Error(
      "Direct governance execution is restricted to Sepolia and local Hardhat. Submit the transaction file through the production governance flow.",
    );
  }

  const [signer] = await ethers.getSigners();
  const signerAddress = address(await signer.getAddress(), "signer");
  if (signerAddress !== config.protocolOwner) {
    throw new Error(
      `Protocol owner mismatch: signer is ${signerAddress}, expected ${config.protocolOwner}`,
    );
  }

  const transactions = readGovernanceBatch(config);
  const fromIndex = arg("from-index");
  if ((hasFlag("from-index") && !fromIndex) || fromIndex?.trim() === "") {
    throw new Error("--from-index requires a zero-based index");
  }
  const startIndex = Number(fromIndex ?? "0");
  if (
    !Number.isInteger(startIndex) ||
    startIndex < 0 ||
    startIndex > transactions.length
  ) {
    throw new Error(
      `--from-index must be between 0 and ${transactions.length}`,
    );
  }
  for (let index = 0; index < transactions.length; index++) {
    const tx = transactions[index];
    if (tx.operation !== 0) {
      throw new Error(`Transaction ${index + 1} is not a CALL operation`);
    }
  }
  for (let index = startIndex; index < transactions.length; index++) {
    const tx = transactions[index];
    try {
      const response = await signer.sendTransaction({
        to: tx.to,
        value: BigInt(tx.value),
        data: tx.data,
      });
      const receipt = await response.wait();
      if (!receipt || receipt.status !== 1) {
        throw new Error(
          `Transaction ${index + 1}/${transactions.length} was not confirmed successfully`,
        );
      }
      console.log(
        `  executed ${index + 1}/${transactions.length}: ${response.hash}. Next index: ${index + 1}`,
      );
    } catch (error) {
      console.error(
        `  failed at ${index + 1}/${transactions.length}. Resume with --from-index ${index} after you confirm that the transaction did not execute.`,
      );
      throw error;
    }
  }
}

function readGovernanceBatch(
  config: ReturnType<typeof loadConfig>,
): SafeTransaction[] {
  const file = safeBatchPath(config);
  if (!fs.existsSync(file)) {
    throw new Error(
      `Governance batch not found: ${file}. Run --action deploy first.`,
    );
  }
  const batch = readJson<{ transactions?: SafeTransaction[] }>(file);
  if (!Array.isArray(batch.transactions)) {
    throw new Error(`Governance batch has no transactions array: ${file}`);
  }
  return batch.transactions;
}

function printProposal(
  proposal: NonNullable<ProtocolDeployment["safeProposal"]>,
) {
  console.log(`
Safe transaction proposed
  hash: ${proposal.safeTxHash}
  nonce: ${proposal.nonce}
  txs:  ${proposal.transactionCount}
  url:  ${proposal.url ?? "(open the Safe UI pending queue)"}
`);
}
