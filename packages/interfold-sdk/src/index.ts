// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Main SDK class
export { InterfoldSDK } from './interfold-sdk'

// Core classes
export { EventListener } from './events/event-listener'
export { ContractClient } from './contracts/contract-client'
export type { ContractClientConfig } from './contracts/contract-client'
export type { EventListenerOptions } from './events/event-listener'

// Standalone encryption functions
export {
  getThresholdBfvParamsSet,
  generatePublicKey,
  computePublicKeyCommitment,
  encryptNumber,
  encryptVector,
  encryptNumberAndGenInputs,
  encryptNumberAndGenProof,
  encryptVectorAndGenInputs,
  encryptVectorAndGenProof,
  generateProof,
} from './crypto'

// Types and interfaces (re-exported from sub-modules via types.ts)
export type {
  SDKConfig,
  ContractAddresses,
  E3,
  E3RequestParams,
  EventListenerConfig,
  EventFilter,
  EventCallback,
  SDKEventEmitter,
  AllEventTypes,
  InterfoldEvent,
  E3RequestedData,
  E3ActivatedData,
  CiphertextOutputPublishedData,
  PlaintextOutputPublishedData,
  CiphernodeAddedData,
  CiphernodeRemovedData,
  CommitteeRequestedData,
  CommitteePublishedData,
  CommitteeFinalizedData,
  InterfoldEventData,
  RegistryEventData,
  BfvParams,
  VerifiableEncryptionResult,
  EncryptedValueAndPublicInputs,
  ThresholdBfvParamsPresetName,
} from './types'

// Enums and constants
export {
  InterfoldEventType,
  RegistryEventType,
  ThresholdBfvParamsPresetNames,
  E3Stage,
  FailureReason,
  CommitteeSize,
  validateCommitteeSize,
} from './types'
export { DEFAULT_THRESHOLD_BFV_PARAMS_PRESET_NAME } from './constants'

// Export utilities
export {
  SDKError,
  isValidAddress,
  isValidHash,
  formatEventName,
  parseEventData,
  formatBigInt,
  parseBigInt,
  generateEventId,
  sleep,
  getCurrentTimestamp,
  DEFAULT_COMPUTE_PROVIDER_PARAMS,
  DEFAULT_E3_CONFIG,
  encodeBfvParams,
  encodeComputeProviderParams,
  encodeCustomParams,
  calculateInputWindow,
  decodePlaintextOutput,
  type ComputeProviderParams,
} from './utils'
