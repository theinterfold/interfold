// SPDX-License-Identifier: LGPL-3.0-only
import fs from "fs";

import { getProxyAdmin } from "../proxy";
import { syncSaleDeploymentRecords } from "../deploymentRecords";
import { connect, hasFlag, networkName } from "./cli";
import { ZERO } from "./constants";
import {
  deploymentPath,
  planPath,
  readJson,
  writeJson,
} from "./files";
import {
  planConfigHash,
  readPlanForConfig,
  writeSaleUiManifest,
} from "./plan";
import {
  buildSaleSafeActions,
  errorMessage,
  printSafeTransactionFallback,
  proposeSafeTransactions,
  proposeSaleSafeActions,
  safeActionsToTransactions,
  writeSafeTransactionFallback,
} from "./safe";
import type {
  DeploymentFile,
  HardhatEthers,
  SafeProposal,
  SaleConfigFile,
  SalePlan,
} from "./types";
import {
  address,
  loadConfig,
  saleConfigStruct,
} from "./values";

export async function deployFromPlan(
  ethers: HardhatEthers,
  config: SaleConfigFile,
  plan: SalePlan,
): Promise<DeploymentFile> {
  const liveNonce = await ethers.provider.getTransactionCount(
    config.saleDeployer,
  );
  if (liveNonce !== plan.factoryNonce) {
    throw new Error(
      `saleDeployer nonce moved: plan=${plan.factoryNonce}, live=${liveNonce}. Run --action plan again.`,
    );
  }

  const deployer = await ethers.getContractAt(
    "InterfoldTokenSaleDeployer",
    config.saleDeployer,
  );
  const [operator] = await ethers.getSigners();
  const operatorAddress = await operator.getAddress();

  console.log(`Submitting deploySale for ${config.name}`);
  console.log(`  expected FOLD:    ${plan.predictedFold}`);
  console.log(`  expected auction: ${plan.predictedAuction}`);

  const tx = await deployer.deploySale(
    saleConfigStruct(plan),
    plan.foldInitCode,
  );
  console.log(`  tx: ${tx.hash}`);
  const receipt = await tx.wait();
  if (!receipt) throw new Error("deploySale transaction was not mined");

  const event = receipt.logs
    .map((log: { topics: ReadonlyArray<string>; data: string }) => {
      try {
        return deployer.interface.parseLog(log);
      } catch {
        return null;
      }
    })
    .find((parsed: { name: string } | null) => parsed?.name === "SaleDeployed");

  const fold = address(event?.args?.fold as string, "SaleDeployed.fold");
  const auction = address(
    event?.args?.auction as string,
    "SaleDeployed.auction",
  );
  if (fold !== plan.predictedFold || auction !== plan.predictedAuction) {
    throw new Error(`Address mismatch: got fold=${fold}, auction=${auction}`);
  }

  const deployment: DeploymentFile = {
    name: config.name,
    chainId: config.chainId,
    txHash: tx.hash,
    blockNumber: receipt.blockNumber,
    operator: operatorAddress,
    safe: config.safe,
    saleDeployer: config.saleDeployer,
    fold,
    auction,
    bondingRegistry: config.fold.bondingRegistry,
    bondingRegistryProxyAdmin: await getProxyAdmin(
      ethers.provider,
      config.fold.bondingRegistry,
    ),
    ccaFactory: plan.ccaFactory,
    validationHook:
      config.auction.validationHook === ZERO
        ? undefined
        : config.auction.validationHook,
    predicateRegistry: config.predicateHook?.registry,
    predicatePolicyID: config.predicateHook?.policyID,
    predicateRequireSenderIsOwner: config.predicateHook?.requireSenderIsOwner,
  };
  writeJson(deploymentPath(config), deployment);
  writeSaleUiManifest(config, plan, deployment);
  syncSaleDeploymentRecords(deployment, plan, {
    chain: networkName(),
    blockNumber: receipt.blockNumber,
  });

  const safeOrigin = `Interfold ${config.name} sale Safe activation`;
  const safeActions = buildSaleSafeActions(config, deployment);
  const safeFallback = writeSafeTransactionFallback(
    config,
    safeActions,
    safeOrigin,
  );
  if (hasFlag("propose-safe")) {
    try {
      const proposal = await proposeSafeTransactions(
        config,
        safeActionsToTransactions(safeActions),
        safeOrigin,
      );
      deployment.safeProposal = proposal;
      writeJson(deploymentPath(config), deployment);
      writeSaleUiManifest(config, plan, deployment);
      console.log(`
Safe transaction proposed
  hash: ${proposal.safeTxHash}
  nonce: ${proposal.nonce}
  url:  ${proposal.url ?? "(open the Safe UI pending queue)"}
`);
    } catch (error) {
      printSafeTransactionFallback(
        config,
        safeFallback,
        `Safe API proposal failed: ${errorMessage(error)}`,
      );
    }
  } else {
    printSafeTransactionFallback(
      config,
      safeFallback,
      "run again with --propose-safe to propose this batch through the Safe SDK",
    );
  }
  console.log(`
Sale deployed
  FOLD:    ${fold}
  auction: ${auction}
  tx:      ${tx.hash}
  config hash: ${planConfigHash(plan)}
`);
  return deployment;
}

export async function actionDeploy(): Promise<void> {
  const { ethers } = await connect();
  const config = loadConfig();
  const plan = await readPlanForConfig(config);
  await deployFromPlan(ethers, config, plan);
}

export async function actionAcceptOwnership(): Promise<void> {
  const { ethers } = await connect();
  const config = loadConfig();
  const deployment = readJson<DeploymentFile>(deploymentPath(config));
  const fold = await ethers.getContractAt("InterfoldToken", deployment.fold);
  const tx = await fold.acceptOwnership();
  await tx.wait();
  console.log(`Accepted FOLD ownership: ${deployment.fold}`);
}

export async function actionProposeSafe(): Promise<void> {
  const config = loadConfig();
  const deployment = readJson<DeploymentFile>(deploymentPath(config));
  let proposal: SafeProposal;
  try {
    proposal = await proposeSaleSafeActions(config, deployment);
  } catch (error) {
    const origin = `Interfold ${config.name} sale Safe activation`;
    const safeFallback = writeSafeTransactionFallback(
      config,
      buildSaleSafeActions(config, deployment),
      origin,
    );
    printSafeTransactionFallback(
      config,
      safeFallback,
      `Safe API proposal failed: ${errorMessage(error)}`,
    );
    process.exitCode = 1;
    return;
  }
  deployment.safeProposal = proposal;
  writeJson(deploymentPath(config), deployment);
  if (fs.existsSync(planPath(config))) {
    writeSaleUiManifest(
      config,
      readJson<SalePlan>(planPath(config)),
      deployment,
    );
  }

  console.log(`
Safe transaction proposed
  hash: ${proposal.safeTxHash}
  nonce: ${proposal.nonce}
  txs:  ${proposal.transactionCount}
  url:  ${proposal.url ?? "(open the Safe UI pending queue)"}
`);
}

