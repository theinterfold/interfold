// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { SDKError } from '../utils'

export interface ContractAddresses {
  interfold: `0x${string}`
  ciphernodeRegistry: `0x${string}`
  feeToken: `0x${string}`
}

/** On-chain `IInterfold.CommitteeSize`: Minimum (N=3), Micro (N=9), Small (N=19). */
export enum CommitteeSize {
  Minimum = 0,
  Micro = 1,
  Small = 2,
}

/** Fail fast on out-of-range committee sizes before they hit the contract. */
export function validateCommitteeSize(value: number | CommitteeSize): CommitteeSize {
  if (!Number.isInteger(value) || value < CommitteeSize.Minimum || value > CommitteeSize.Small) {
    throw new SDKError(
      `Invalid committeeSize ${value}. Use CommitteeSize.Minimum (0), CommitteeSize.Micro (1), or CommitteeSize.Small (2).`,
      'INVALID_COMMITTEE_SIZE',
    )
  }
  return value
}

export enum ParamSet {
  Insecure512 = 0,
  Secure8192 = 1,
}

export interface E3 {
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
  plaintextOutput: string
}

export interface RequestParams {
  gasLimit?: bigint
}

export interface E3RequestParams extends RequestParams {
  committeeSize: number
  inputWindow: readonly [bigint, bigint]
  e3Program: `0x${string}`
  paramSet: number
  computeProviderParams: `0x${string}`
  customParams?: `0x${string}`
  /** When true, ciphernodes generate wrapper/fold proofs for DKG proof aggregation.
   *  When false, proof aggregation is skipped for faster computation. Defaults to true. */
  proofAggregationEnabled?: boolean
}

export enum E3Stage {
  None,
  Requested,
  CommitteeFinalized,
  KeyPublished,
  CiphertextReady,
  Complete,
  Failed,
}

export enum FailureReason {
  None,
  CommitteeFormationTimeout,
  InsufficientCommitteeMembers,
  DKGTimeout,
  DKGInvalidShares,
  NoInputsReceived,
  ComputeTimeout,
  ComputeProviderExpired,
  ComputeProviderFailed,
  RequesterCancelled,
  DecryptionTimeout,
  DecryptionInvalidShares,
  VerificationFailed,
}
