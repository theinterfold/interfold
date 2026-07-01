// SPDX-License-Identifier: LGPL-3.0-only
import type { MetaTransactionData } from "@safe-global/types-kit";

import type { connect } from "./cli";

export type HardhatEthers = Awaited<ReturnType<typeof connect>>["ethers"];

export interface FoldTokenConfig {
  ccaStart: string;
  ccaEnd: string;
  noMoreLocks?: string;
  bondingRegistry: string;
}

export interface AuctionConfig {
  currency: string;
  tokensRecipient: string;
  fundsRecipient: string;
  startBlock: string;
  endBlock: string;
  claimBlock: string;
  tickSpacing: string;
  validationHook: string;
  floorPrice: string;
  requiredCurrencyRaised: string;
  auctionStepsData: string;
}

export interface PredicateHookConfig {
  registry: string;
  policyID: string;
  address?: string;
  requireSenderIsOwner?: boolean;
}

export interface SaleConfigFile {
  name: string;
  chainId: number;
  saleDeployer: string;
  safe: string;
  ccaFactory?: string;
  saleAmount: string;
  ccaSalt: string;
  saleLabel: string;
  fold: FoldTokenConfig;
  auction: AuctionConfig;
  predicateHook?: PredicateHookConfig;
}

export interface AuctionParameters {
  currency: string;
  tokensRecipient: string;
  fundsRecipient: string;
  startBlock: bigint;
  endBlock: bigint;
  claimBlock: bigint;
  tickSpacing: bigint;
  validationHook: string;
  floorPrice: bigint;
  requiredCurrencyRaised: bigint;
  auctionStepsData: string;
}

export interface SalePlan {
  name: string;
  chainId: number;
  saleDeployer: string;
  safe: string;
  factoryNonce: number;
  ccaFactory: string;
  predictedFold: string;
  predictedAuction: string;
  fold: {
    initialOwner: string;
    ccaStart: string;
    ccaEnd: string;
    noMoreLocks: string;
    claimSource: string;
    bondingRegistry: string;
  };
  auction: AuctionParameters;
  saleConfig: {
    ccaFactory: string;
    saleAmount: string;
    ccaSalt: string;
    ccaConfigData: string;
    saleLabel: string;
    foldInitCodeHash: string;
  };
  foldInitCode: string;
  configHash?: string;
  configDigest?: string;
}

export interface DeploymentFile {
  name: string;
  chainId: number;
  txHash: string;
  blockNumber: number;
  operator: string;
  safe: string;
  saleDeployer: string;
  fold: string;
  auction: string;
  bondingRegistry: string;
  bondingRegistryProxyAdmin?: string;
  ccaFactory: string;
  validationHook?: string;
  predicateRegistry?: string;
  predicatePolicyID?: string;
  predicateRequireSenderIsOwner?: boolean;
  mockCcaFactory?: string;
  testBidId?: string;
  safeProposal?: SafeProposal;
}

export interface SafeProposal {
  safeTxHash: string;
  safeAddress: string;
  proposer: string;
  nonce: number;
  transactionCount: number;
  origin: string;
  url?: string;
  proposedAt: string;
}

export interface SafeAction {
  description: string;
  transaction: MetaTransactionData;
}

export interface SafeTransactionFallbackFile {
  name: string;
  chainId: number;
  safe: string;
  origin: string;
  createdAt: string;
  transactions: Array<{
    description: string;
    to: string;
    value: string;
    data: string;
    operation: number;
  }>;
}

