// SPDX-License-Identifier: LGPL-3.0-only
import { ethers as ethersLib } from "ethers";

import { encodeSchedule, generateSchedule } from "../ccaSchedule";
import { arg, hasFlag } from "./cli";
import {
  DAY,
  DEFAULT_SALE_AMOUNT,
  ZERO,
} from "./constants";
import type { PredicateHookConfig, SaleConfigFile } from "./types";
import { address } from "./values";

export function makeTemplateConfig(opts: {
  name: string;
  chainId: number;
  safe: string;
  saleDeployer: string;
  bondingRegistry: string;
  ccaFactory: string;
  currentBlock: bigint;
  currentTimestamp: bigint;
}): SaleConfigFile {
  const offsetSeconds = BigInt(arg("cca-offset-seconds") ?? String(DAY));
  const durationSeconds = BigInt(
    arg("cca-duration-seconds") ?? String(7n * DAY),
  );
  const ccaStart = opts.currentTimestamp + offsetSeconds;
  const ccaEnd = ccaStart + durationSeconds;
  const startBlock = opts.currentBlock + 2n;
  const endBlock = startBlock + BigInt(arg("auction-duration-blocks") ?? "40");
  const auctionBlocks = Number(endBlock - startBlock);
  const auctionStepsData = encodeSchedule(
    generateSchedule({
      auctionBlocks: auctionBlocks - 1,
      prebidBlocks: 0,
      numSteps: Math.min(12, Math.max(1, auctionBlocks - 1)),
      finalBlockPct: 0.3,
      alpha: 1.2,
    }),
  );
  const floorPrice = "4295000000";
  return {
    name: opts.name,
    chainId: opts.chainId,
    safe: opts.safe,
    saleDeployer: opts.saleDeployer,
    ccaFactory: opts.ccaFactory,
    saleAmount: arg("sale-amount") ?? DEFAULT_SALE_AMOUNT,
    ccaSalt: ethersLib.id(`${opts.name}:${opts.chainId}:${Date.now()}`),
    saleLabel: arg("sale-label") ?? "cca-sale",
    fold: {
      ccaStart: ccaStart.toString(),
      ccaEnd: ccaEnd.toString(),
      noMoreLocks: "",
      bondingRegistry: opts.bondingRegistry,
    },
    auction: {
      currency: "ETH",
      tokensRecipient: opts.safe,
      fundsRecipient: opts.safe,
      startBlock: startBlock.toString(),
      endBlock: endBlock.toString(),
      claimBlock: (endBlock + 1n).toString(),
      tickSpacing: "100000",
      validationHook: ZERO,
      floorPrice,
      requiredCurrencyRaised: "0",
      auctionStepsData,
    },
  };
}

function nonZero(value?: string): string | undefined {
  if (!value?.trim()) return undefined;
  return value === ZERO ? undefined : value;
}

export function resolvePredicateHookInput(
  config?: SaleConfigFile,
): PredicateHookConfig | undefined {
  const addressInput =
    arg("predicate-hook") ??
    arg("validation-hook") ??
    nonZero(config?.predicateHook?.address) ??
    nonZero(config?.auction.validationHook);
  const registryInput =
    arg("predicate-registry") ??
    process.env.PREDICATE_REGISTRY ??
    config?.predicateHook?.registry;
  const policyID =
    arg("predicate-policy-id") ??
    process.env.PREDICATE_POLICY_ID ??
    config?.predicateHook?.policyID;

  if (!addressInput && !registryInput && !policyID) return undefined;

  const requireSenderIsOwner = hasFlag("predicate-allow-delegated-owner")
    ? false
    : (config?.predicateHook?.requireSenderIsOwner ?? true);

  if (!addressInput && (!registryInput || !policyID)) {
    throw new Error(
      "Predicate hook deployment requires --predicate-registry and --predicate-policy-id.",
    );
  }
  if (registryInput && !policyID) {
    throw new Error("Predicate hook config requires a policy ID.");
  }

  return {
    registry: registryInput
      ? address(registryInput, "predicateHook.registry")
      : ZERO,
    policyID: policyID ?? "",
    address: addressInput
      ? address(addressInput, "predicateHook.address")
      : undefined,
    requireSenderIsOwner,
  };
}

