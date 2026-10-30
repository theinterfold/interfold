// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { ProofData } from '@aztec-foundation/bb.js'
import type { CircuitInputs } from './user-data-encryption'

export interface BfvParams {
  degree: number
  plaintextModulus: bigint
  moduli: bigint[]
  error1Variance: string | undefined
}

/**
 * On-chain parameter sets: `INSECURE_THRESHOLD_64` (0, trBFV), `SECURE_THRESHOLD_8192` (2, trBFV),
 * `SECURE_THRESHOLD_16384` (3, l-BFV) and `INSECURE_THRESHOLD_LBFV` (4, l-BFV, degree 128).
 */
export type ThresholdBfvParamsPresetName =
  | 'INSECURE_THRESHOLD_64'
  | 'INSECURE_THRESHOLD_LBFV'
  | 'SECURE_THRESHOLD_8192'
  | 'SECURE_THRESHOLD_16384'

export const ThresholdBfvParamsPresetNames = [
  'INSECURE_THRESHOLD_64',
  'INSECURE_THRESHOLD_LBFV',
  'SECURE_THRESHOLD_8192',
  'SECURE_THRESHOLD_16384',
] as const satisfies ReadonlyArray<ThresholdBfvParamsPresetName>

export interface VerifiableEncryptionResult {
  encryptedData: Uint8Array
  proof: ProofData
}

export interface EncryptedValueAndPublicInputs {
  encryptedData: Uint8Array
  circuitInputs: CircuitInputs
}

export interface BfvParamSet {
  name: ThresholdBfvParamsPresetName
  params: BfvParams
}
