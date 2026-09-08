// SPDX-License-Identifier: LGPL-3.0-only

export interface TimeoutConfig {
  dkgWindow: string;
  computeWindow: string;
  decryptionWindow: string;
}

export interface PricingConfig {
  /** Non-refundable fee-token amount charged for one accepted randomness request. */
  randomnessFlatFee: string;
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

export interface RandomnessConfig {
  /** Chainlink VRF v2.5 coordinator for the deployment chain. */
  coordinator: string;
  /** Existing, funded subscription owned by the protocol owner. */
  subscriptionId: string;
  /** Gas lane key hash published for the deployment chain. */
  keyHash: string;
  requestConfirmations: number;
  callbackGasLimit: number;
  nativePayment: boolean;
  /** Admission floor checked at deployment and before each VRF request. */
  minimumSubscriptionBalance: string;
  /** Maximum seconds to wait before the requester can cancel a request. */
  requestTimeout: string;
}

export interface ProtocolConfigFile {
  name: string;
  chainId: number;
  /** Address that owns the protocol contracts and executes the wiring calls. */
  protocolOwner: string;
  /** Optional Safe address when the protocol owner is itself a Safe. */
  safe?: string;
  /** Optional Aragon Admin plugin route for DAO-owned protocol deployments. */
  governance?: {
    adminPlugin: string;
    proposerSafe: string;
    proposalMetadata?: string;
  };
  fold: string;
  /**
   * Optional escrow IVotes adapter. When set, only FOLD locked in that escrow carries voting
   * power and idle wallet FOLD carries none — operators keep their weight by bonding instead.
   * Omit to count wallet-held FOLD, which is the original behaviour.
   */
  escrowVotesAdapter?: string;
  bondingRegistryProxy: string;
  bondingRegistryProxyAdmin: string;
  feeToken: string;
  feeTokenDecimals: number;
  ticketUnderlyingToken: string;
  protocolTreasury: string;
  slashedFundsTreasury: string;
  slasher: string;
  randomness?: RandomnessConfig;
  ticketToken: { lockRegistry: boolean };
  bonding: {
    ticketPrice: string;
    requiredCiphernodeBond: string;
    ticketTokenDecimals: number;
    ciphernodeBondTokenDecimals: number;
    minTicketBalance: string;
    exitDelay: string;
  };
  /**
   * Bond owners to resynchronize when a `bondingRegistry` upgrade first attaches
   * `BondedCheckpoints`. Configuring the contract does not backfill, so an owner that bonded
   * beforehand reads as zero bonded voting power until its next bond, slash, exit claim or owner
   * transfer. Collect the list off-chain from `BondOwnerSet` and `CiphernodeBondUpdated` logs. Only
   * needed on a deployment that already has bonds; a first-time deployment has none.
   */
  bondedResyncOwners?: string[];
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
    registerActiveBfvParamSet: boolean;
    allowFeeToken: boolean;
  };
  verifiers?: {
    /** Deploy the generated BFV verifier stack with this protocol deployment. */
    deploy?: boolean;
    decryptionVerifier?: string;
    pkVerifier?: string;
    dkgFoldAttestationVerifier?: string;
    /**
     * The protocol ciphertext verifier for the BFV scheme, e.g. `Risc0BfvCiphertextVerifier`.
     *
     * This is the contract that checks the compute receipt before an E3 reaches
     * `CiphertextReady`. Its `imageId` is immutable, so replacing it is a redeployment, not a
     * setter call on the existing one. Leaving it unset ships a protocol with no ciphertext
     * verification for the scheme.
     */
    ciphertextVerifier?: string;
  };
  ciphertextVerifier?: string;
  /** Deploy a stateless always-accepting ciphertext verifier for rehearsal deployments. */
  deployMockCiphertextVerifier?: boolean;
  /** Deploy the stateless MockE3Program as the initial E3 program. */
  deployMockE3Program?: boolean;
  bindInitialE3Program?: boolean;
  e3Programs: [string];
}

export interface BfvVerifierRouteDeployment {
  preset: string;
  committee: string;
  paramSet: number;
  committeeSize: number;
  decryptionVerifier: string;
  pkVerifier: string;
  dkgAggregatorVerifier: string;
  decryptionAggregatorVerifier: string;
  verifierZkTranscriptLib: string;
  dkgVerifierRelationsLib: string;
  decryptionVerifierRelationsLib: string;
}

export interface ProtocolDeployment {
  name: string;
  chainId: number;
  operator: string;
  protocolOwner: string;
  safe?: string;
  fold: string;
  feeToken: string;
  ticketUnderlyingToken: string;
  bondingRegistryProxy: string;
  bondingRegistryProxyAdmin: string;
  bondingRegistryImplementation: string;
  bondingAssetLib: string;
  bondingEligibilityLib: string;
  bondingSlashingLib: string;
  bondingRegistrationLib: string;
  bondingOwnershipLib: string;
  nodeReleaseRegistry: string;
  bondedCheckpoints: string;
  /**
   * Deployed by `--action activate-voting`, after the governance batch initializes the registry: the
   * `BondedVotes` constructor rejects a registry that does not yet bond the token it reads.
   */
  bondedVotes?: string;
  decryptionVerifier?: string;
  pkVerifier?: string;
  dkgFoldAttestationVerifier?: string;
  dkgAggregatorVerifier?: string;
  decryptionAggregatorVerifier?: string;
  verifierZkTranscriptLib?: string;
  dkgVerifierRelationsLib?: string;
  decryptionVerifierRelationsLib?: string;
  bfvVerifierRoutes?: BfvVerifierRouteDeployment[];
  ciphertextVerifier?: string;
  crispProgram?: string;
  dataAvailabilityVerifier?: string;
  initialE3Program: string;
  ticketToken: string;
  slashingManager: string;
  slashingEvidenceLib: string;
  poseidonT3: string;
  registrySortitionLib: string;
  randomnessProvider: string;
  /** Exact randomness settings used to deploy and validate the recorded provider. */
  randomness?: RandomnessConfig;
  randomnessProviderOwnershipAcceptanceRequired?: boolean;
  ciphernodeRegistry: string;
  ciphernodeRegistryImplementation: string;
  ciphernodeRegistryProxyAdmin: string;
  interfold: string;
  interfoldImplementation: string;
  interfoldProxyAdmin: string;
  interfoldLifecycle: string;
  interfoldPricing: string;
  e3RefundManager: string;
  e3RefundManagerImplementation: string;
  e3RefundManagerProxyAdmin: string;
  safeTransactions: string;
  governanceSafeBuilder?: string;
  safeProposal?: SafeProposal;
}

export interface VrfSortitionUpgradePlan {
  name: string;
  operator: string;
  protocolOwner: string;
  registryProxy: string;
  registryProxyAdmin: string;
  registryImplementation: string;
  sortitionLibrary: string;
  interfoldProxy: string;
  interfoldProxyAdmin: string;
  interfoldImplementation: string;
  lifecycleLibrary: string;
  pricingLibrary: string;
  bondingProxy: string;
  bondingProxyAdmin: string;
  bondingImplementation: string;
  bondingAssetLibrary: string;
  bondingEligibilityLibrary: string;
  bondingSlashingLibrary: string;
  bondingRegistrationLibrary: string;
  bondingOwnershipLibrary: string;
  nodeReleaseRegistry: string;
  nodeRelease: {
    version: string;
    protocolVersion: number;
    nodeGeneration: number;
    releaseId: string;
  };
  randomnessProvider: string;
  randomness: RandomnessConfig;
  randomnessFlatFee: string;
  randomnessProviderOwnershipAcceptanceRequired: boolean;
  safeTransactions: string;
  governanceSafeBuilder?: string;
  safeProposal?: SafeProposal;
}

export interface SecureCrispUpgradePlan {
  name: string;
  chainId: number;
  operator: string;
  protocolOwner: string;
  interfoldProxy: string;
  interfoldProxyAdmin: string;
  interfoldImplementation: string;
  lifecycleLibrary: string;
  pricingLibrary: string;
  registryProxy: string;
  registryProxyAdmin: string;
  registryImplementation: string;
  sortitionLibrary: string;
  nodeReleaseRegistry: string;
  nodeRelease: {
    version: string;
    protocolVersion: number;
    nodeGeneration: number;
    releaseId: string;
  };
  cryptoConfigId: string;
  paramSet: number;
  pkVerifier: string;
  decryptionVerifier: string;
  ciphertextVerifier: string;
  crispProgram: string;
  /** Bootstrap mock closed to new requests by this activation, when present. */
  retiredE3Program?: string;
  dataAvailabilityVerifier: string;
  inputAvailabilitySigner: string;
  availBridge: string;
  vectorx: string;
  bfvVerifierRoutes: BfvVerifierRouteDeployment[];
  safeTransactions: string;
  governanceSafeBuilder?: string;
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
  slashingEvidenceLib: string;
  poseidonT3: string;
  registrySortitionLib: string;
  randomnessProvider: string;
  randomnessProviderOwnershipAcceptanceRequired?: boolean;
  ciphernodeRegistry: string;
  ciphernodeRegistryImplementation: string;
  ciphernodeRegistryProxyAdmin: string;
  interfold: string;
  interfoldImplementation: string;
  interfoldProxyAdmin: string;
  interfoldLifecycle: string;
  interfoldPricing: string;
  e3RefundManager: string;
  e3RefundManagerImplementation: string;
  e3RefundManagerProxyAdmin: string;
  bondingRegistryImplementation: string;
  bondingAssetLib: string;
  bondingEligibilityLib: string;
  bondingSlashingLib: string;
  bondingRegistrationLib: string;
  bondingOwnershipLib: string;
  nodeReleaseRegistry: string;
  bondedCheckpoints: string;
  /**
   * Deployed by `--action activate-voting`, after the governance batch initializes the registry: the
   * `BondedVotes` constructor rejects a registry that does not yet bond the token it reads.
   */
  bondedVotes?: string;
  decryptionVerifier?: string;
  pkVerifier?: string;
  dkgFoldAttestationVerifier?: string;
  dkgAggregatorVerifier?: string;
  decryptionAggregatorVerifier?: string;
  verifierZkTranscriptLib?: string;
  dkgVerifierRelationsLib?: string;
  decryptionVerifierRelationsLib?: string;
  bfvVerifierRoutes?: BfvVerifierRouteDeployment[];
  ciphertextVerifier?: string;
  initialE3Program: string;
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
  nodeRelease: {
    encodeFunctionData: (name: string, values?: readonly unknown[]) => string;
  };
}

export interface ProtocolDeployResult {
  contracts: ProtocolContracts;
  interfaces: ProtocolInterfaces;
}
