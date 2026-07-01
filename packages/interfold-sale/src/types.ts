// SPDX-License-Identifier: LGPL-3.0-only

export interface WalletProvider {
  request(args: { method: string; params?: unknown[] | Record<string, unknown> }): Promise<unknown>
  on?(event: 'accountsChanged' | 'chainChanged', listener: (...args: unknown[]) => void): void
  removeListener?(event: 'accountsChanged' | 'chainChanged', listener: (...args: unknown[]) => void): void
}

declare global {
  interface Window {
    ethereum?: WalletProvider
  }
}

export interface AuctionConfig {
  currency: string
  tokensRecipient: string
  fundsRecipient: string
  startBlock: string
  endBlock: string
  claimBlock: string
  tickSpacing: string
  validationHook: string
  floorPrice: string
  requiredCurrencyRaised: string
  auctionStepsData: string
}

export interface SaleDeployment {
  name: string
  chainId: number
  txHash: string
  blockNumber: number
  operator: string
  safe: string
  saleDeployer: string
  fold: string
  auction: string
  bondingRegistry: string
  bondingRegistryProxyAdmin?: string
  ccaFactory: string
  validationHook?: string
  predicateRegistry?: string
  predicatePolicyID?: string
  predicateRequireSenderIsOwner?: boolean
  saleAmount: string
  saleLabel: string
  ccaVersion: string
  auctionConfig?: AuctionConfig
  testBidId?: string
  foldSchedule?: {
    ccaStart: string
    ccaEnd: string
    noMoreLocks: string
  }
  mockCcaFactory?: string
}

export interface LockEntry {
  policyId: string
  amount: bigint
  queued: boolean
}

export interface OnchainState {
  blockNumber: bigint
  blockTimestamp: bigint
  tokenSupply: bigint
  totalFoldSupply: bigint
  currencyRaised?: bigint
  currencyBalance: bigint
  currencyDecimals: number
  currencySymbol: string
  isGraduated?: boolean
  tokensReceived?: boolean
  foldBalance: bigint
  lockedBalance: bigint
  transferableBalance: bigint
  totalBonded: bigint
  lockCount: bigint
  queuedLockCount: bigint
  locks: LockEntry[]
  owner?: string
  pendingOwner?: string
  tgeTimestamp?: bigint
  phase?: number
  roles: {
    admin: boolean
    minter: boolean
    lockManager: boolean
    whitelist: boolean
  }
}

export interface BidRecord {
  id: string
  amount: string
  price: string
  txHash: string
}

export interface PredicateAttestation {
  uuid: string
  expiration: string | number | bigint
  attester: string
  signature: string
}

export interface PredicateAttestationResponse {
  is_compliant?: boolean
  attestation?: PredicateAttestation
  reason?: { code?: string; message?: string }
  error?: string
}

export interface Profile {
  id: string
  name: string
  account: string
  amount: string
  policyId: string
  label: string
}

export interface EventRow {
  id: string
  source: 'FOLD' | 'CCA'
  title: string
  detail: string
  blockNumber: number
  txHash: string
}

export interface EventLogLike {
  address?: string
  args?: EventArgs
  blockNumber: number | bigint
  fragment?: { name?: string }
  index?: number
  transactionHash: string
}

export type EventArgs = Record<string, unknown>
export type RouteName = 'auction' | 'admin'

export interface AuctionStep {
  index: number
  mps: bigint
  blockDelta: bigint
  supply: bigint
  startOffset: bigint
  endOffset: bigint
}

export interface SubmittedTx {
  hash: string
  wait(): Promise<unknown>
}
