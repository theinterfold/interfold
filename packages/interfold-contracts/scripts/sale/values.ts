// SPDX-License-Identifier: LGPL-3.0-only
import { ethers as ethersLib } from "ethers";

import { decodeSchedule } from "../ccaSchedule";
import { arg } from "./cli";
import {
  abi,
  AUCTION_PARAMETERS_TUPLE,
  CCA_FACTORY_ADDRESS,
  CCA_VERSION,
  FORTY_DAYS,
  FOUR_YEARS,
  MSG_SENDER_SENTINEL,
  ZERO,
} from "./constants";
import { configPath, readJson } from "./files";
import type { AuctionConfig, AuctionParameters, SaleConfigFile, SalePlan } from "./types";

export function address(value: string, label: string): string {
  try {
    return ethersLib.getAddress(value);
  } catch {
    throw new Error(`${label} is not a valid address: ${value}`);
  }
}

export function requireBytes32(value: string, label: string): string {
  if (!/^0x[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error(`${label} must be a 0x-prefixed bytes32`);
  }
  return value;
}

function validateAuctionStepsData(
  auctionStepsData: string,
  startBlock: bigint,
  endBlock: bigint,
): void {
  const schedule = decodeSchedule(auctionStepsData);
  const totalBlocks = schedule.reduce((sum, step) => sum + step.blockDelta, 0n);
  const windowBlocks = endBlock - startBlock;
  if (totalBlocks !== windowBlocks) {
    throw new Error(
      `auctionStepsData covers ${totalBlocks} blocks, but auction window is ${windowBlocks}`,
    );
  }
}

export function loadConfig(file = configPath()): SaleConfigFile {
  const config = readJson<SaleConfigFile>(file);
  const safeOverride = arg("safe") ?? process.env.SAFE_ADDRESS;
  const saleDeployerOverride = arg("sale-deployer");
  const bondingOverride = arg("bonding-registry");
  const ccaFactoryOverride = arg("cca-factory");

  if (safeOverride && config.safe === ZERO) config.safe = safeOverride;
  if (saleDeployerOverride && config.saleDeployer === ZERO) {
    config.saleDeployer = saleDeployerOverride;
  }
  if (bondingOverride && config.fold.bondingRegistry === ZERO) {
    config.fold.bondingRegistry = bondingOverride;
  }
  if (ccaFactoryOverride) config.ccaFactory = ccaFactoryOverride;

  validateConfig(config);
  return config;
}

export function validateConfig(config: SaleConfigFile): void {
  if (!config.name) throw new Error("Config name is required");
  const legacyVersion = (config as SaleConfigFile & { ccaVersion?: unknown })
    .ccaVersion;
  if (legacyVersion !== undefined && legacyVersion !== CCA_VERSION) {
    throw new Error(
      `ccaVersion is no longer configurable; remove it or set it to ${CCA_VERSION}`,
    );
  }
  delete (config as SaleConfigFile & { ccaVersion?: unknown }).ccaVersion;
  config.safe = address(config.safe, "safe");
  config.saleDeployer = address(config.saleDeployer, "saleDeployer");
  if (config.ccaFactory) {
    config.ccaFactory = address(config.ccaFactory, "ccaFactory");
  }
  config.fold.bondingRegistry = address(
    config.fold.bondingRegistry,
    "fold.bondingRegistry",
  );
  config.auction.tokensRecipient = address(
    config.auction.tokensRecipient,
    "auction.tokensRecipient",
  );
  config.auction.fundsRecipient = address(
    config.auction.fundsRecipient,
    "auction.fundsRecipient",
  );
  config.auction.validationHook = address(
    config.auction.validationHook || ZERO,
    "auction.validationHook",
  );
  if (config.predicateHook) {
    config.predicateHook.registry = address(
      config.predicateHook.registry,
      "predicateHook.registry",
    );
    if (config.predicateHook.address?.trim()) {
      config.predicateHook.address = address(
        config.predicateHook.address,
        "predicateHook.address",
      );
      if (config.auction.validationHook === ZERO) {
        config.auction.validationHook = config.predicateHook.address;
      }
    }
    if (!config.predicateHook.policyID?.trim()) {
      throw new Error(
        "predicateHook.policyID is required when predicateHook is set",
      );
    }
  }
  requireBytes32(config.ccaSalt, "ccaSalt");
  ethersLib.encodeBytes32String(config.saleLabel);
  BigInt(config.saleAmount);
  BigInt(config.fold.ccaStart);
  BigInt(config.fold.ccaEnd);
  if (config.fold.noMoreLocks?.trim()) BigInt(config.fold.noMoreLocks);
}

export function resolveCurrency(currency: string): string {
  if (!currency || currency.toUpperCase() === "ETH") return ZERO;
  return address(currency, "auction.currency");
}

export function toAuctionParameters(config: AuctionConfig): AuctionParameters {
  const startBlock = BigInt(config.startBlock);
  const endBlock = BigInt(config.endBlock);
  const claimBlock = BigInt(config.claimBlock);
  if (endBlock <= startBlock) {
    throw new Error("auction.endBlock must be greater than auction.startBlock");
  }
  if (claimBlock < endBlock) {
    throw new Error("auction.claimBlock must be >= auction.endBlock");
  }
  const auctionStepsData = config.auctionStepsData || "0x";
  if (!ethersLib.isHexString(auctionStepsData)) {
    throw new Error("auction.auctionStepsData must be 0x-prefixed hex");
  }
  validateAuctionStepsData(auctionStepsData, startBlock, endBlock);
  return {
    currency: resolveCurrency(config.currency),
    tokensRecipient: address(config.tokensRecipient, "auction.tokensRecipient"),
    fundsRecipient: address(config.fundsRecipient, "auction.fundsRecipient"),
    startBlock,
    endBlock,
    claimBlock,
    tickSpacing: BigInt(config.tickSpacing),
    validationHook: address(
      config.validationHook || ZERO,
      "auction.validationHook",
    ),
    floorPrice: BigInt(config.floorPrice),
    requiredCurrencyRaised: BigInt(config.requiredCurrencyRaised),
    auctionStepsData,
  };
}

export function encodeAuctionConfigData(params: AuctionParameters): string {
  return abi.encode(
    [AUCTION_PARAMETERS_TUPLE],
    [
      [
        params.currency,
        params.tokensRecipient,
        params.fundsRecipient,
        params.startBlock,
        params.endBlock,
        params.claimBlock,
        params.tickSpacing,
        params.validationHook,
        params.floorPrice,
        params.requiredCurrencyRaised,
        params.auctionStepsData,
      ],
    ],
  );
}

export function resolveCcaFactory(config: SaleConfigFile): string {
  return address(config.ccaFactory ?? CCA_FACTORY_ADDRESS, "ccaFactory");
}

export function deriveNoMoreLocks(ccaEnd: bigint, explicit?: string): bigint {
  if (explicit?.trim()) {
    const value = BigInt(explicit);
    const minimum = ccaEnd + FORTY_DAYS;
    if (value <= minimum) {
      throw new Error(
        `fold.noMoreLocks must be greater than ccaEnd + 40 days (${minimum})`,
      );
    }
    return value;
  }
  return ccaEnd + FORTY_DAYS + FOUR_YEARS;
}

export function buildFoldInitCode(opts: {
  creationCode: string;
  initialOwner: string;
  ccaStart: bigint;
  ccaEnd: bigint;
  noMoreLocks: bigint;
  claimSource: string;
  bondingRegistry: string;
}): string {
  const encodedCtor = abi.encode(
    ["address", "uint64", "uint64", "uint64", "address", "address"],
    [
      opts.initialOwner,
      opts.ccaStart,
      opts.ccaEnd,
      opts.noMoreLocks,
      opts.claimSource,
      opts.bondingRegistry,
    ],
  );
  return ethersLib.concat([opts.creationCode, encodedCtor]);
}

export function saleConfigStruct(plan: SalePlan) {
  return {
    ccaFactory: plan.saleConfig.ccaFactory,
    saleAmount: BigInt(plan.saleConfig.saleAmount),
    ccaSalt: plan.saleConfig.ccaSalt,
    ccaConfigData: plan.saleConfig.ccaConfigData,
    saleLabel: plan.saleConfig.saleLabel,
    foldInitCodeHash: plan.saleConfig.foldInitCodeHash,
  };
}

export function resolvedRecipient(value: string, sender: string): string {
  return value.toLowerCase() === MSG_SENDER_SENTINEL
    ? address(sender, "sender")
    : address(value, "recipient");
}

export async function codeAt(
  provider: ethersLib.Provider,
  target: string,
): Promise<string> {
  return provider.getCode(target);
}

export async function requireContract(
  provider: ethersLib.Provider,
  target: string,
  label: string,
): Promise<void> {
  const code = await codeAt(provider, target);
  if (code === "0x") throw new Error(`${label} has no code: ${target}`);
}

export async function deployedAddress(contract: {
  target?: unknown;
  getAddress?: () => Promise<string>;
}): Promise<string> {
  if (typeof contract.target === "string") {
    return address(contract.target, "contract");
  }
  if (contract.getAddress) {
    return address(await contract.getAddress(), "contract");
  }
  throw new Error("Could not determine deployed contract address");
}

export function assertEq(label: string, actual: unknown, expected: unknown): void {
  if (String(actual).toLowerCase() !== String(expected).toLowerCase()) {
    throw new Error(`${label}: expected ${expected}, got ${actual}`);
  }
  console.log(`  ok ${label}`);
}

export function formatFold(value: bigint | string): string {
  return `${ethersLib.formatUnits(value, 18)} FOLD`;
}

export async function optionalView<T>(
  label: string,
  read: () => Promise<T>,
): Promise<T | undefined> {
  try {
    return await read();
  } catch {
    console.log(`  skip ${label} (view not available)`);
    return undefined;
  }
}

