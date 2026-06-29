// SPDX-License-Identifier: LGPL-3.0-only

export interface TimeoutConfig {
  dkgWindow: string;
  computeWindow: string;
  decryptionWindow: string;
}

export interface PricingConfig {
  keyGenFixedPerNode: string;
  keyGenPerEncryptionProof: string;
  coordinationPerPair: string;
  availabilityPerNodePerSec: string;
  decryptionPerNode: string;
  publicationBase: string;
  verificationPerProof: string;
  protocolTreasury: string;
  marginBps: string;
  protocolShareBps: string;
  dkgUtilizationBps: string;
  computeUtilizationBps: string;
  decryptUtilizationBps: string;
  minCommitteeSize: string;
  minThreshold: string;
}

export interface ProtocolConfigFile {
  name: string;
  chainId: number;
  safe: string;
  fold: string;
  bondingRegistryProxy: string;
  bondingRegistryProxyAdmin: string;
  feeToken: string;
  protocolTreasury: string;
  slashedFundsTreasury: string;
  slasher: string;
  ticketToken: { lockRegistry: boolean };
  bonding: {
    ticketPrice: string;
    licenseRequiredBond: string;
    minTicketBalance: string;
    exitDelay: string;
  };
  registry: { sortitionSubmissionWindow: string };
  slashing: { initialDelay: string };
  interfold: {
    maxDuration: string;
    markFailedGracePeriod: string;
    timeoutConfig: TimeoutConfig;
    pricing: PricingConfig;
    committeeThresholds: Array<{
      size: string;
      quorum: string;
      total: string;
    }>;
    registerDefaultBfvParamSets: boolean;
    allowFeeToken: boolean;
  };
  verifiers?: {
    decryptionVerifier?: string;
    pkVerifier?: string;
    dkgFoldAttestationVerifier?: string;
  };
  e3Programs?: string[];
}

export interface ProtocolDeployment {
  name: string;
  chainId: number;
  operator: string;
  safe: string;
  fold: string;
  feeToken: string;
  bondingRegistryProxy: string;
  bondingRegistryProxyAdmin: string;
  bondingRegistryImplementation: string;
  ticketToken: string;
  slashingManager: string;
  poseidonT3: string;
  ciphernodeRegistry: string;
  ciphernodeRegistryImplementation: string;
  ciphernodeRegistryProxyAdmin: string;
  interfold: string;
  interfoldImplementation: string;
  interfoldProxyAdmin: string;
  interfoldPricing: string;
  e3RefundManager: string;
  e3RefundManagerImplementation: string;
  e3RefundManagerProxyAdmin: string;
  safeTransactions: string;
  safeProposal?: SafeProposal;
}

export interface SafeTransaction {
  to: string;
  value: string;
  data: string;
  operation: number;
  contractMethod: null;
  contractInputsValues: null;
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

export interface ProtocolContracts {
  ticketToken: string;
  slashingManager: string;
  poseidonT3: string;
  ciphernodeRegistry: string;
  ciphernodeRegistryImplementation: string;
  ciphernodeRegistryProxyAdmin: string;
  interfold: string;
  interfoldImplementation: string;
  interfoldProxyAdmin: string;
  interfoldPricing: string;
  e3RefundManager: string;
  e3RefundManagerImplementation: string;
  e3RefundManagerProxyAdmin: string;
  bondingRegistryImplementation: string;
}

export interface ProtocolInterfaces {
  ticket: {
    encodeFunctionData: (name: string, values?: readonly unknown[]) => string;
  };
  slashing: {
    encodeFunctionData: (name: string, values?: readonly unknown[]) => string;
  };
  registry: {
    encodeFunctionData: (name: string, values?: readonly unknown[]) => string;
  };
  interfold: {
    encodeFunctionData: (name: string, values?: readonly unknown[]) => string;
  };
  bonding: {
    encodeFunctionData: (name: string, values?: readonly unknown[]) => string;
  };
}

export interface ProtocolDeployResult {
  contracts: ProtocolContracts;
  interfaces: ProtocolInterfaces;
}
