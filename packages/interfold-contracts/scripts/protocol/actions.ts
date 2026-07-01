// SPDX-License-Identifier: LGPL-3.0-only
import { ethers as ethersLib } from "ethers";
import fs from "fs";

import { connect, hasFlag, networkName } from "./cli";
import { proxyAdminInterface } from "./constants";
import { deployProtocolContracts } from "./deployContracts";
import {
  deploymentPath,
  readJson,
  safeBatchPath,
  writeJson,
} from "./files";
import { proposeSafeBatch, safeBatch } from "./safe";
import { buildSafeTransactions } from "./transactions";
import type { ProtocolDeployment, SafeTransaction } from "./types";
import { address, loadConfig, requireContract } from "./values";
import { syncProtocolDeploymentRecords } from "../deploymentRecords";

async function assertPreconditions(
  ethers: any,
  config: ReturnType<typeof loadConfig>,
) {
  await Promise.all([
    requireContract(ethers.provider, config.safe, "safe"),
    requireContract(ethers.provider, config.fold, "fold"),
    requireContract(ethers.provider, config.feeToken, "feeToken"),
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
  ]);

  const proxyAdmin = new ethersLib.Contract(
    config.bondingRegistryProxyAdmin,
    proxyAdminInterface,
    ethers.provider,
  );
  const proxyAdminOwner = address(await proxyAdmin.owner(), "proxyAdmin.owner");
  if (proxyAdminOwner !== config.safe) {
    throw new Error(
      `BondingRegistry ProxyAdmin owner mismatch: expected ${config.safe}, got ${proxyAdminOwner}`,
    );
  }
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
  writeJson(batchFile, safeBatch(config, txs));

  const deployment: ProtocolDeployment = {
    name: config.name,
    chainId,
    operator: operatorAddress,
    safe: config.safe,
    fold: config.fold,
    feeToken: config.feeToken,
    bondingRegistryProxy: config.bondingRegistryProxy,
    bondingRegistryProxyAdmin: config.bondingRegistryProxyAdmin,
    ...result.contracts,
    safeTransactions: batchFile,
  };
  const deploymentFile = deploymentPath(config);
  writeJson(deploymentFile, deployment);
  syncProtocolDeploymentRecords(config, deployment, result.interfaces, {
    chain: networkName(),
    blockNumber,
    syncIntegrationConfig: hasFlag("sync-integration-config"),
  });

  if (hasFlag("propose-safe")) {
    deployment.safeProposal = await proposeSafeBatch(config, txs);
    writeJson(deploymentFile, deployment);
    printProposal(deployment.safeProposal);
  }

  console.log(`
Protocol contracts deployed
  ticketToken:            ${deployment.ticketToken}
  slashingManager:        ${deployment.slashingManager}
  ciphernodeRegistry:     ${deployment.ciphernodeRegistry}
  interfold:              ${deployment.interfold}
  e3RefundManager:        ${deployment.e3RefundManager}
  bonding implementation: ${deployment.bondingRegistryImplementation}

Safe batch required
  file: ${batchFile}
  txs:  ${txs.length}

Deployment file
  ${deploymentFile}
`);
}

export async function actionProposeSafe(): Promise<void> {
  const config = loadConfig();
  const transactions = readSafeBatch(config);
  const proposal = await proposeSafeBatch(config, transactions);

  if (fs.existsSync(deploymentPath(config))) {
    const deployment = readJson<ProtocolDeployment>(deploymentPath(config));
    deployment.safeProposal = proposal;
    writeJson(deploymentPath(config), deployment);
  }

  printProposal(proposal);
}

function readSafeBatch(
  config: ReturnType<typeof loadConfig>,
): SafeTransaction[] {
  const file = safeBatchPath(config);
  if (!fs.existsSync(file)) {
    throw new Error(
      `Safe batch not found: ${file}. Run --action deploy first.`,
    );
  }
  const batch = readJson<{ transactions?: SafeTransaction[] }>(file);
  if (!Array.isArray(batch.transactions)) {
    throw new Error(`Safe batch has no transactions array: ${file}`);
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
