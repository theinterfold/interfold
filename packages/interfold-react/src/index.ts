// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * @interfold/react
 *
 * React hooks and utilities for Interfold SDK
 */

export { useInterfoldSDK } from './useInterfoldSDK'
export type { UseInterfoldSDKConfig, UseInterfoldSDKReturn } from './useInterfoldSDK'

// Re-export commonly used types from the main SDK for convenience
export type {
  AllEventTypes,
  EventCallback,
  InterfoldEvent,
  E3RequestedData,
  E3ActivatedData,
  CiphertextOutputPublishedData,
  PlaintextOutputPublishedData,
  CiphernodeAddedData,
  CiphernodeRemovedData,
  CommitteeRequestedData,
  CommitteePublishedData,
} from '@interfold/sdk'

export { InterfoldEventType, RegistryEventType } from '@interfold/sdk'
