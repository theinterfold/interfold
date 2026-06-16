// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { ProofData } from '@aztec/bb.js'
import type { CircuitInputs } from './user-data-encryption'

export interface BfvParams {
  degree: number
  plaintextModulus: bigint
  moduli: bigint[]
  error1Variance: string | undefined
}

export type ThresholdBfvParamsPresetName = 'INSECURE_THRESHOLD_512' | 'SECURE_THRESHOLD_8192'

export const ThresholdBfvParamsPresetNames = [
  'INSECURE_THRESHOLD_512',
  'SECURE_THRESHOLD_8192',
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
