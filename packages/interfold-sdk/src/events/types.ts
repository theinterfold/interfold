// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { Log } from 'viem'

export enum InterfoldEventType {
  E3_REQUESTED = 'E3Requested',
  CIPHERTEXT_OUTPUT_PUBLISHED = 'CiphertextOutputPublished',
  CIPHERTEXT_OUTPUT_REFERENCE_PUBLISHED = 'CiphertextOutputReferencePublished',
  PLAINTEXT_OUTPUT_PUBLISHED = 'PlaintextOutputPublished',
  E3_PROGRAM_REGISTERED = 'E3ProgramRegistered',
  ENCRYPTION_SCHEME_ENABLED = 'EncryptionSchemeEnabled',
  CIPHERNODE_REGISTRY_SET = 'CiphernodeRegistrySet',
  MAX_DURATION_SET = 'MaxDurationSet',
  PARAM_SET_REGISTERED = 'ParamSetRegistered',
  OWNERSHIP_TRANSFERRED = 'OwnershipTransferred',
  INITIALIZED = 'Initialized',
}

export enum RegistryEventType {
  COMMITTEE_REQUESTED = 'CommitteeRequested',
  COMMITTEE_RANDOMNESS_REQUESTED = 'CommitteeRandomnessRequested',
  RANDOMNESS_CIRCUIT_BREAKER_TRIPPED = 'RandomnessCircuitBreakerTripped',
  COMMITTEE_PUBLISHED = 'CommitteePublished',
  COMMITTEE_PUBLIC_KEY_CHUNK_PUBLISHED = 'CommitteePublicKeyChunkPublished',
  COMMITTEE_FINALIZED = 'SortitionCommitteeFinalized',
  INTERFOLD_SET = 'InterfoldSet',
  OWNERSHIP_TRANSFERRED = 'OwnershipTransferred',
  INITIALIZED = 'Initialized',
}

export enum RandomnessProviderEventType {
  RANDOMNESS_FULFILLED = 'RandomnessFulfilled',
}

export type AllEventTypes = InterfoldEventType | RegistryEventType

export interface E3RequestedData {
  e3Id: bigint
  e3: {
    seed: bigint
    committeeSize: number
    requestBlock: bigint
    inputWindow: readonly [bigint, bigint]
    encryptionSchemeId: string
    e3Program: string
    paramSet: number
    decryptionVerifier: string
    committeePublicKey: string
    ciphertextOutput: string
    ciphertextCommitment: string
    plaintextOutput: string
  }
  cryptoConfigId: string
}

export interface E3ActivatedData {
  e3Id: bigint
  expiration: bigint
  committeePublicKey: string
}

export interface CiphertextOutputPublishedData {
  e3Id: bigint
  ciphertextOutput: string
  ciphertextCommitment: string
}

export interface CiphertextOutputReferencePublishedData {
  e3Id: bigint
  contentHash: string
  ciphertextCommitment: string
  availabilityBlock: number
  availabilityLeafIndex: bigint
}

export interface PlaintextOutputPublishedData {
  e3Id: bigint
  plaintextOutput: string
  proof: string
}

export interface CiphernodeAddedData {
  node: string
  index: bigint
  numNodes: bigint
  size: bigint
}

export interface CiphernodeRemovedData {
  node: string
  index: bigint
  numNodes: bigint
  size: bigint
}

export interface CommitteeRequestedData {
  e3Id: bigint
  entropyBlock: bigint
  threshold: [bigint, bigint]
  requestBlock: bigint
  committeeDeadline: bigint
  ticketPrice: bigint
}

export interface CommitteeRandomnessRequestedData {
  e3Id: bigint
  requestId: bigint
  provider: string
  randomnessDeadline: bigint
}

export interface RandomnessCircuitBreakerTrippedData {
  e3Id: bigint
  requestId: bigint
  randomnessProvider: string
}

export interface RandomnessFulfilledData {
  requestId: bigint
  e3Id: bigint
  randomWord: bigint
  fulfilledAt: bigint
}

export interface CommitteePublishedData {
  e3Id: bigint
  nodes: string[]
  publicKey: string
  pkCommitment: string
  proof: string
}

export interface CommitteePublicKeyChunkPublishedData {
  e3Id: bigint
  publisher: string
  candidateHash: string
  nodes: string[]
  pkCommitment: string
  chunkIndex: number
  chunkCount: number
  totalLength: number
  chunk: string
}

export interface CommitteeFinalizedData {
  e3Id: bigint
  committee: string[]
  scores: bigint[]
}

export interface InterfoldEventData {
  [InterfoldEventType.E3_REQUESTED]: E3RequestedData
  [InterfoldEventType.CIPHERTEXT_OUTPUT_PUBLISHED]: CiphertextOutputPublishedData
  [InterfoldEventType.CIPHERTEXT_OUTPUT_REFERENCE_PUBLISHED]: CiphertextOutputReferencePublishedData
  [InterfoldEventType.PLAINTEXT_OUTPUT_PUBLISHED]: PlaintextOutputPublishedData
  [InterfoldEventType.E3_PROGRAM_REGISTERED]: { e3Program: string }
  [InterfoldEventType.ENCRYPTION_SCHEME_ENABLED]: { encryptionSchemeId: string }
  [InterfoldEventType.CIPHERNODE_REGISTRY_SET]: { ciphernodeRegistry: string }
  [InterfoldEventType.MAX_DURATION_SET]: { maxDuration: bigint }
  [InterfoldEventType.PARAM_SET_REGISTERED]: { paramSet: number; encodedParams: string }
  [InterfoldEventType.OWNERSHIP_TRANSFERRED]: { previousOwner: string; newOwner: string }
  [InterfoldEventType.INITIALIZED]: { version: bigint }
}

export interface RegistryEventData {
  [RegistryEventType.COMMITTEE_REQUESTED]: CommitteeRequestedData
  [RegistryEventType.COMMITTEE_RANDOMNESS_REQUESTED]: CommitteeRandomnessRequestedData
  [RegistryEventType.RANDOMNESS_CIRCUIT_BREAKER_TRIPPED]: RandomnessCircuitBreakerTrippedData
  [RegistryEventType.COMMITTEE_PUBLISHED]: CommitteePublishedData
  [RegistryEventType.COMMITTEE_PUBLIC_KEY_CHUNK_PUBLISHED]: CommitteePublicKeyChunkPublishedData
  [RegistryEventType.COMMITTEE_FINALIZED]: CommitteeFinalizedData
  [RegistryEventType.INTERFOLD_SET]: { interfold: string }
  [RegistryEventType.OWNERSHIP_TRANSFERRED]: { previousOwner: string; newOwner: string }
  [RegistryEventType.INITIALIZED]: { version: bigint }
}

export interface InterfoldEvent<T extends AllEventTypes> {
  type: T
  data: T extends InterfoldEventType ? InterfoldEventData[T] : T extends RegistryEventType ? RegistryEventData[T] : unknown
  log: Log
  timestamp: Date
  blockNumber: bigint
  transactionHash: string
}

export interface RandomnessProviderEvent<T extends RandomnessProviderEventType = RandomnessProviderEventType> {
  type: T
  data: RandomnessFulfilledData
  provider: `0x${string}`
  log: Log
  timestamp: Date
  blockNumber: bigint
  transactionHash: string
}

export type RandomnessProviderEventCallback<T extends RandomnessProviderEventType = RandomnessProviderEventType> = (
  event: RandomnessProviderEvent<T>,
) => void | Promise<void>

export type EventCallback<T extends AllEventTypes = AllEventTypes> = (event: InterfoldEvent<T>) => void | Promise<void>

export interface EventFilter<T = unknown> {
  address?: `0x${string}`
  fromBlock?: bigint
  toBlock?: bigint
  args?: Partial<T>
}

export interface SDKEventEmitter {
  on<T extends AllEventTypes>(eventType: T, callback: EventCallback<T>): void
  off<T extends AllEventTypes>(eventType: T, callback: EventCallback<T>): void
  emit<T extends AllEventTypes>(event: InterfoldEvent<T>): void
}

export interface EventListenerConfig {
  fromBlock?: bigint
  toBlock?: bigint
  /** Maximum block span for each historical RPC query. */
  historicalBlockRange?: bigint
  polling?: boolean
  pollingInterval?: number
}
