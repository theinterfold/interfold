// SPDX-License-Identifier: LGPL-3.0-only
import { ethers as ethersLib } from "ethers";
import fs from "fs";
import path from "path";

import {
  CCA_FACTORY_ABI,
  CCA_VERSION,
} from "./constants";
import {
  planPath,
  readJson,
  saleUiDir,
  writeJson,
} from "./files";
import type { DeploymentFile, HardhatEthers, SaleConfigFile, SalePlan } from "./types";
import {
  address,
  buildFoldInitCode,
  deriveNoMoreLocks,
  encodeAuctionConfigData,
  requireContract,
  resolveCcaFactory,
  saleConfigStruct,
  toAuctionParameters,
} from "./values";

export async function buildSalePlan(
  ethers: HardhatEthers,
  config: SaleConfigFile,
): Promise<SalePlan> {
  const network = await ethers.provider.getNetwork();
  const chainId = Number(network.chainId);
  if (chainId !== config.chainId) {
    throw new Error(
      `Connected chainId ${chainId} != config.chainId ${config.chainId}`,
    );
  }

  await requireContract(ethers.provider, config.saleDeployer, "saleDeployer");
  await requireContract(
    ethers.provider,
    config.fold.bondingRegistry,
    "fold.bondingRegistry",
  );

  const saleDeployer = await ethers.getContractAt(
    "InterfoldTokenSaleDeployer",
    config.saleDeployer,
  );
  const protocolAdmin = address(
    await saleDeployer.protocolAdmin(),
    "protocolAdmin",
  );
  if (protocolAdmin !== config.safe) {
    throw new Error(
      `saleDeployer.protocolAdmin mismatch: expected ${config.safe}, got ${protocolAdmin}`,
    );
  }

  const ccaFactory = resolveCcaFactory(config);
  await requireContract(ethers.provider, ccaFactory, "ccaFactory");

  const latest = await ethers.provider.getBlock("latest");
  if (!latest) throw new Error("Could not read latest block");
  const ccaStart = BigInt(config.fold.ccaStart);
  const ccaEnd = BigInt(config.fold.ccaEnd);
  if (ccaStart <= BigInt(latest.timestamp)) {
    throw new Error(
      `fold.ccaStart (${ccaStart}) must be in the future; latest timestamp is ${latest.timestamp}`,
    );
  }
  if (ccaEnd <= ccaStart) {
    throw new Error("fold.ccaEnd must be after fold.ccaStart");
  }
  const noMoreLocks = deriveNoMoreLocks(ccaEnd, config.fold.noMoreLocks);

  const factoryNonce = await ethers.provider.getTransactionCount(
    config.saleDeployer,
  );
  const predictedFold = ethersLib.getCreateAddress({
    from: config.saleDeployer,
    nonce: BigInt(factoryNonce),
  });
  const auctionParams = toAuctionParameters(config.auction);
  const ccaConfigData = encodeAuctionConfigData(auctionParams);
  const saleAmount = BigInt(config.saleAmount);
  if (saleAmount > (1n << 128n) - 1n) {
    throw new Error("saleAmount exceeds uint128 max");
  }

  const cca = new ethersLib.Contract(
    ccaFactory,
    CCA_FACTORY_ABI,
    ethers.provider,
  );
  const predictedAuction = await cca[
    "getAddress(address,uint256,bytes,bytes32,address)"
  ](
    predictedFold,
    saleAmount,
    ccaConfigData,
    config.ccaSalt,
    config.saleDeployer,
  );

  const foldFactory = await ethers.getContractFactory("InterfoldToken");
  const foldInitCode = buildFoldInitCode({
    creationCode: foldFactory.bytecode,
    initialOwner: config.saleDeployer,
    ccaStart,
    ccaEnd,
    noMoreLocks,
    claimSource: predictedAuction,
    bondingRegistry: config.fold.bondingRegistry,
  });
  const foldInitCodeHash = ethersLib.keccak256(foldInitCode);

  const plan: SalePlan = {
    name: config.name,
    chainId,
    saleDeployer: config.saleDeployer,
    safe: config.safe,
    factoryNonce,
    ccaFactory,
    predictedFold,
    predictedAuction: address(predictedAuction, "predictedAuction"),
    fold: {
      initialOwner: config.saleDeployer,
      ccaStart: ccaStart.toString(),
      ccaEnd: ccaEnd.toString(),
      noMoreLocks: noMoreLocks.toString(),
      claimSource: address(predictedAuction, "predictedAuction"),
      bondingRegistry: config.fold.bondingRegistry,
    },
    auction: auctionParams,
    saleConfig: {
      ccaFactory,
      saleAmount: saleAmount.toString(),
      ccaSalt: config.ccaSalt,
      ccaConfigData,
      saleLabel: ethersLib.encodeBytes32String(config.saleLabel),
      foldInitCodeHash,
    },
    foldInitCode,
  };
  plan.configHash = await saleDeployer.hashConfig(saleConfigStruct(plan));
  return plan;
}

export function printPlan(plan: SalePlan, planFile: string): void {
  console.log(`
Interfold sale plan
  config:        ${plan.name}
  chainId:       ${plan.chainId}
  safe:          ${plan.safe}
  saleDeployer:  ${plan.saleDeployer}
  factoryNonce:  ${plan.factoryNonce}
  ccaFactory:    ${plan.ccaFactory}
  FOLD:          ${plan.predictedFold}
  CCA auction:   ${plan.predictedAuction}
  bondingRegistry proxy: ${plan.fold.bondingRegistry}
  FOLD timestamps: start=${plan.fold.ccaStart} end=${plan.fold.ccaEnd} noMoreLocks=${plan.fold.noMoreLocks}
  CCA blocks:    start=${plan.auction.startBlock} end=${plan.auction.endBlock} claim=${plan.auction.claimBlock}
  config hash:   ${planConfigHash(plan)}
  plan file:     ${planFile}
`);
}

export function planConfigHash(plan: SalePlan): string {
  const hash = plan.configHash ?? plan.configDigest;
  if (!hash) {
    throw new Error("Plan is missing configHash. Run --action plan again.");
  }
  return hash;
}

export async function readPlanForConfig(
  config: SaleConfigFile,
): Promise<SalePlan> {
  const file = planPath(config);
  if (!fs.existsSync(file)) {
    throw new Error(`Plan file not found: ${file}. Run --action plan first.`);
  }
  return readJson<SalePlan>(file);
}

export function writeSaleUiManifest(
  config: SaleConfigFile,
  plan: SalePlan,
  deployment: DeploymentFile,
): void {
  const dir = saleUiDir();
  writeJson(path.join(dir, "config.json"), config);
  writeJson(path.join(dir, "plan.json"), plan);
  writeJson(path.join(dir, "deployment.json"), {
    ...deployment,
    saleAmount: config.saleAmount,
    saleLabel: config.saleLabel,
    ccaVersion: CCA_VERSION,
    auctionConfig: config.auction,
    foldSchedule: {
      ccaStart: config.fold.ccaStart,
      ccaEnd: config.fold.ccaEnd,
      noMoreLocks: plan.fold.noMoreLocks,
    },
  });
}

