// SPDX-License-Identifier: LGPL-3.0-only
import { ethers as ethersLib } from "ethers";
import fs from "fs";

import { connect, hasFlag } from "./cli";
import {
  CCA_AUCTION_ABI,
  PREDICATE_VALIDATION_HOOK_ABI,
  ZERO,
} from "./constants";
import {
  deploymentPath,
  planPath,
  readJson,
} from "./files";
import {
  buildSalePlan,
  planConfigHash,
  readPlanForConfig,
} from "./plan";
import type { DeploymentFile, HardhatEthers, SaleConfigFile, SalePlan } from "./types";
import {
  address,
  assertEq,
  formatFold,
  loadConfig,
  optionalView,
  requireContract,
  resolveCurrency,
  resolvedRecipient,
} from "./values";

function formatTimestamp(value: bigint | string): string {
  const seconds = BigInt(value);
  const iso = new Date(Number(seconds) * 1000).toISOString();
  return `${seconds} (${iso})`;
}

function formatBlockDelta(target: bigint, current: bigint): string {
  if (target >= current) return `${target - current} block(s) from now`;
  return `${current - target} block(s) ago`;
}

function formatSecondsDelta(target: bigint, current: bigint): string {
  if (target >= current) return `${target - current}s from now`;
  return `${current - target}s ago`;
}

function printValue(label: string, value: unknown): void {
  console.log(`     ${label}: ${String(value)}`);
}

function printValidationSummary(
  config: SaleConfigFile,
  deployment: DeploymentFile,
  plan: SalePlan,
  currentBlock: bigint,
  currentTimestamp: bigint,
): void {
  console.log(`
Sale deployment
  name:              ${deployment.name}
  chainId:           ${deployment.chainId}
  deploy tx:         ${deployment.txHash}
  deploy block:      ${deployment.blockNumber}
  operator:          ${deployment.operator}
  safe:              ${deployment.safe}
  saleDeployer:      ${deployment.saleDeployer}
  FOLD:              ${deployment.fold}
  CCA auction:       ${deployment.auction}
  bondingRegistry:   ${deployment.bondingRegistry}
  proxyAdmin:        ${deployment.bondingRegistryProxyAdmin ?? "(unknown)"}
  ccaFactory:        ${deployment.ccaFactory}
  validationHook:    ${deployment.validationHook ?? ZERO}
  config hash:       ${planConfigHash(plan)}

Predicted addresses
  FOLD:              ${plan.predictedFold}
  CCA auction:       ${plan.predictedAuction}
  saleDeployer nonce:${plan.factoryNonce}

FOLD lifecycle
  current timestamp: ${formatTimestamp(currentTimestamp)}
  CCA_START:         ${formatTimestamp(config.fold.ccaStart)} (${formatSecondsDelta(BigInt(config.fold.ccaStart), currentTimestamp)})
  CCA_END:           ${formatTimestamp(config.fold.ccaEnd)} (${formatSecondsDelta(BigInt(config.fold.ccaEnd), currentTimestamp)})
  NO_MORE_LOCKS:     ${formatTimestamp(plan.fold.noMoreLocks)} (${formatSecondsDelta(BigInt(plan.fold.noMoreLocks), currentTimestamp)})

CCA schedule
  current block:     ${currentBlock}
  startBlock:        ${config.auction.startBlock} (${formatBlockDelta(BigInt(config.auction.startBlock), currentBlock)})
  endBlock:          ${config.auction.endBlock} (${formatBlockDelta(BigInt(config.auction.endBlock), currentBlock)})
  claimBlock:        ${config.auction.claimBlock} (${formatBlockDelta(BigInt(config.auction.claimBlock), currentBlock)})

Economics and recipients
  saleAmount:        ${config.saleAmount} (${formatFold(config.saleAmount)})
  currency:          ${config.auction.currency} -> ${resolveCurrency(config.auction.currency)}
  floorPrice:        ${config.auction.floorPrice}
  tickSpacing:       ${config.auction.tickSpacing}
  requiredRaised:    ${config.auction.requiredCurrencyRaised}
  tokensRecipient:   ${config.auction.tokensRecipient}
  fundsRecipient:    ${config.auction.fundsRecipient}
  auctionSteps bytes:${(config.auction.auctionStepsData.length - 2) / 2}
`);

  if (deployment.safeProposal) {
    console.log(`Safe proposal
  hash:              ${deployment.safeProposal.safeTxHash}
  nonce:             ${deployment.safeProposal.nonce}
  txs:               ${deployment.safeProposal.transactionCount}
  url:               ${deployment.safeProposal.url ?? "(open Safe UI)"}
`);
  }
}

async function validateAuctionFundingNotification(
  ethers: HardhatEthers,
  auction: ethersLib.Contract,
  config: SaleConfigFile,
  deployment: DeploymentFile,
): Promise<void> {
  const receipt = await ethers.provider.getTransactionReceipt(
    deployment.txHash,
  );
  const auctionAddress = deployment.auction.toLowerCase();
  const tokensReceivedEvent = receipt?.logs
    .filter((log) => log.address.toLowerCase() === auctionAddress)
    .map((log) => {
      try {
        return auction.interface.parseLog(log);
      } catch {
        return null;
      }
    })
    .find((parsed) => parsed?.name === "TokensReceived");

  if (tokensReceivedEvent) {
    assertEq(
      "auction.TokensReceived.totalSupply",
      tokensReceivedEvent.args.totalSupply,
      config.saleAmount,
    );
    printValue(
      "TokensReceived totalSupply",
      `${tokensReceivedEvent.args.totalSupply} (${formatFold(tokensReceivedEvent.args.totalSupply)})`,
    );
    return;
  }

  const tokensReceived = await optionalView("auction.tokensReceived", () =>
    auction.tokensReceived(),
  );
  if (tokensReceived !== undefined) {
    assertEq("auction.tokensReceived", tokensReceived, true);
  }
}

export async function actionValidate(): Promise<void> {
  const { ethers } = await connect();
  const config = loadConfig();
  const deployment = readJson<DeploymentFile>(deploymentPath(config));
  const plan = fs.existsSync(planPath(config))
    ? await readPlanForConfig(config)
    : await buildSalePlan(ethers, config);
  await validateDeployment(ethers, config, deployment, plan);
}

export async function validateDeployment(
  ethers: HardhatEthers,
  config: SaleConfigFile,
  deployment: DeploymentFile,
  plan: SalePlan,
  allowPendingOwner = hasFlag("allow-pending-owner"),
): Promise<void> {
  const latest = await ethers.provider.getBlock("latest");
  if (!latest) throw new Error("Could not read latest block");
  const currentBlock = BigInt(latest.number);
  const currentTimestamp = BigInt(latest.timestamp);

  const saleDeployer = await ethers.getContractAt(
    "InterfoldTokenSaleDeployer",
    deployment.saleDeployer,
  );
  const fold = await ethers.getContractAt("InterfoldToken", deployment.fold);
  const auction = new ethersLib.Contract(
    deployment.auction,
    CCA_AUCTION_ABI,
    ethers.provider,
  );

  console.log(`Validating ${deployment.name}`);
  printValidationSummary(
    config,
    deployment,
    plan,
    currentBlock,
    currentTimestamp,
  );

  const protocolAdmin = await saleDeployer.protocolAdmin();
  assertEq("saleDeployer.protocolAdmin", protocolAdmin, config.safe);
  printValue("protocolAdmin", protocolAdmin);

  const claimSource = await fold.CLAIM_SOURCE();
  assertEq("FOLD.CLAIM_SOURCE", claimSource, deployment.auction);
  printValue("claimSource", claimSource);

  const bondingRegistry = await fold.BONDING_REGISTRY();
  assertEq("FOLD.BONDING_REGISTRY", bondingRegistry, config.fold.bondingRegistry);
  printValue("bondingRegistry", bondingRegistry);
  await requireContract(
    ethers.provider,
    config.fold.bondingRegistry,
    "bondingRegistry",
  );

  const auctionToken = await auction.token();
  assertEq("auction.token", auctionToken, deployment.fold);
  printValue("auction token", auctionToken);

  const auctionTotalSupply = await auction.totalSupply();
  assertEq("auction.totalSupply", auctionTotalSupply, config.saleAmount);
  printValue(
    "auction total supply",
    `${auctionTotalSupply} (${formatFold(auctionTotalSupply)})`,
  );

  const foldTotalSupply = await fold.totalSupply();
  printValue("FOLD total supply", `${foldTotalSupply} (${formatFold(foldTotalSupply)})`);

  const auctionCurrency = await auction.currency();
  assertEq("auction.currency", auctionCurrency, resolveCurrency(config.auction.currency));
  printValue("auction currency", auctionCurrency);

  const tokensRecipient = await auction.tokensRecipient();
  assertEq(
    "auction.tokensRecipient",
    tokensRecipient,
    resolvedRecipient(config.auction.tokensRecipient, config.saleDeployer),
  );
  printValue("tokensRecipient", tokensRecipient);

  const fundsRecipient = await auction.fundsRecipient();
  assertEq(
    "auction.fundsRecipient",
    fundsRecipient,
    resolvedRecipient(config.auction.fundsRecipient, config.saleDeployer),
  );
  printValue("fundsRecipient", fundsRecipient);

  const startBlock = await auction.startBlock();
  assertEq("auction.startBlock", startBlock, config.auction.startBlock);
  printValue("startBlock", `${startBlock} (${formatBlockDelta(BigInt(startBlock), currentBlock)})`);

  const endBlock = await auction.endBlock();
  assertEq("auction.endBlock", endBlock, config.auction.endBlock);
  printValue("endBlock", `${endBlock} (${formatBlockDelta(BigInt(endBlock), currentBlock)})`);

  const claimBlock = await auction.claimBlock();
  assertEq("auction.claimBlock", claimBlock, config.auction.claimBlock);
  printValue("claimBlock", `${claimBlock} (${formatBlockDelta(BigInt(claimBlock), currentBlock)})`);

  const hook = await optionalView("auction.validationHook", () =>
    auction.validationHook(),
  );
  if (hook !== undefined) {
    assertEq("auction.validationHook", hook, config.auction.validationHook);
    printValue("auction validationHook", hook);
  }

  const isGraduated = await optionalView("auction.isGraduated", () =>
    auction.isGraduated(),
  );
  if (isGraduated !== undefined) printValue("auction isGraduated", isGraduated);

  const currencyRaised = await optionalView("auction.currencyRaised", () =>
    auction.currencyRaised(),
  );
  if (currencyRaised !== undefined) printValue("auction currencyRaised", currencyRaised);

  const validationHook =
    deployment.validationHook ?? config.auction.validationHook;
  if (validationHook && validationHook !== ZERO) {
    const predicateHook = new ethersLib.Contract(
      validationHook,
      PREDICATE_VALIDATION_HOOK_ABI,
      ethers.provider,
    );
    const hookOwner = await predicateHook.owner();
    assertEq("validationHook.owner", hookOwner, config.safe);
    printValue("validationHook owner", hookOwner);
    const hookAuction = await predicateHook.auction();
    assertEq("validationHook.auction", hookAuction, deployment.auction);
    printValue("validationHook auction", hookAuction);
    const requireSenderIsOwner = await optionalView(
      "validationHook.requireSenderIsOwner",
      () => predicateHook.requireSenderIsOwner(),
    );
    if (requireSenderIsOwner !== undefined) {
      printValue("validationHook requireSenderIsOwner", requireSenderIsOwner);
    }
    if (config.predicateHook?.registry) {
      const registry = await predicateHook.getRegistry();
      assertEq("validationHook.registry", registry, config.predicateHook.registry);
      printValue("validationHook registry", registry);
    }
    if (config.predicateHook?.policyID) {
      const policyID = await predicateHook.getPolicyID();
      assertEq("validationHook.policyID", policyID, config.predicateHook.policyID);
      printValue("validationHook policyID", policyID);
    }
  }

  await validateAuctionFundingNotification(
    ethers,
    auction,
    config,
    deployment,
  );

  const auctionBalance = await fold.balanceOf(deployment.auction);
  const saleAmount = BigInt(config.saleAmount);
  if (auctionBalance > saleAmount) {
    throw new Error(
      `FOLD auction balance exceeds sale amount: ${auctionBalance} > ${saleAmount}`,
    );
  }
  if (currentBlock < BigInt(config.auction.claimBlock)) {
    assertEq("FOLD auction balance", auctionBalance, saleAmount);
  } else {
    console.log(
      `  ok FOLD auction balance <= sale amount (${auctionBalance}, ${formatFold(auctionBalance)})`,
    );
  }
  printValue(
    "auction FOLD balance",
    `${auctionBalance} (${formatFold(auctionBalance)})`,
  );

  const ccaStart = await fold.CCA_START();
  assertEq("FOLD.CCA_START", ccaStart, config.fold.ccaStart);
  printValue("CCA_START", formatTimestamp(ccaStart));

  const ccaEnd = await fold.CCA_END();
  assertEq("FOLD.CCA_END", ccaEnd, config.fold.ccaEnd);
  printValue("CCA_END", formatTimestamp(ccaEnd));

  const noMoreLocks = await fold.NO_MORE_LOCKS();
  assertEq("FOLD.NO_MORE_LOCKS", noMoreLocks, plan.fold.noMoreLocks);
  printValue("NO_MORE_LOCKS", formatTimestamp(noMoreLocks));

  const tgeTimestamp = await fold.tgeTimestamp();
  assertEq("FOLD.tgeTimestamp", tgeTimestamp, 0);
  printValue("tgeTimestamp", tgeTimestamp);

  const configHash = planConfigHash(plan);
  assertEq("used config hash", await saleDeployer.usedConfigHashes(configHash), true);
  printValue("used config hash", configHash);

  const owner = address(await fold.owner(), "FOLD.owner");
  const pendingOwner = await optionalView("FOLD.pendingOwner", () =>
    fold.pendingOwner(),
  );
  printValue("FOLD owner", owner);
  if (pendingOwner !== undefined) printValue("FOLD pendingOwner", pendingOwner);

  if (owner === config.safe) {
    const defaultAdminRole = ethersLib.ZeroHash;
    const safeDefaultAdmin = await fold.hasRole(defaultAdminRole, config.safe);
    assertEq(
      "Safe DEFAULT_ADMIN_ROLE",
      safeDefaultAdmin,
      true,
    );
    printValue("Safe DEFAULT_ADMIN_ROLE", safeDefaultAdmin);
    if (address(deployment.operator, "deployment.operator") !== config.safe) {
      const operatorDefaultAdmin = await fold.hasRole(
        defaultAdminRole,
        deployment.operator,
      );
      assertEq(
        "operator DEFAULT_ADMIN_ROLE",
        operatorDefaultAdmin,
        false,
      );
      printValue("operator DEFAULT_ADMIN_ROLE", operatorDefaultAdmin);
    } else {
      console.log(
        "  skip operator DEFAULT_ADMIN_ROLE (operator is Safe in this run)",
      );
    }
    const factoryDefaultAdmin = await fold.hasRole(
      defaultAdminRole,
      config.saleDeployer,
    );
    assertEq(
      "factory DEFAULT_ADMIN_ROLE",
      factoryDefaultAdmin,
      false,
    );
    printValue("factory DEFAULT_ADMIN_ROLE", factoryDefaultAdmin);
    const safeMinter = await fold.hasRole(
      ethersLib.id("MINTER_ROLE"),
      config.safe,
    );
    assertEq(
      "Safe MINTER_ROLE",
      safeMinter,
      true,
    );
    printValue("Safe MINTER_ROLE", safeMinter);
    const safeWhitelist = await fold.hasRole(
      ethersLib.id("WHITELIST_ROLE"),
      config.safe,
    );
    assertEq(
      "Safe WHITELIST_ROLE",
      safeWhitelist,
      true,
    );
    printValue("Safe WHITELIST_ROLE", safeWhitelist);
    const safeLockManager = await fold.hasRole(
      ethersLib.id("LOCK_MANAGER_ROLE"),
      config.safe,
    );
    assertEq(
      "Safe LOCK_MANAGER_ROLE",
      safeLockManager,
      true,
    );
    printValue("Safe LOCK_MANAGER_ROLE", safeLockManager);
  } else {
    const normalizedPendingOwner = address(
      String(pendingOwner),
      "FOLD.pendingOwner",
    );
    if (allowPendingOwner && normalizedPendingOwner === config.safe) {
      console.log("  ok FOLD ownership is pending Safe acceptance");
    } else {
      throw new Error(
        `FOLD owner is ${owner}; expected accepted Safe ${config.safe}`,
      );
    }
  }

  console.log("Validation complete");
}
