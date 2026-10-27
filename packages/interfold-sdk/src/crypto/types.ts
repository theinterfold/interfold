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
 * `INSECURE_THRESHOLD_64` and `SECURE_THRESHOLD_8192` run the trBFV path. The other presets run the
 * l-BFV path: `INSECURE_THRESHOLD_LBFV` (N=128, on-chain parameter set 4), `INSECURE_THRESHOLD_SIMD`,
 * `SECURE_THRESHOLD_16384`, `SECURE_THRESHOLD_16384_SIMD` (N=16384, plaintext modulus 65537,
 * on-chain parameter set 6) and `SECURE_THRESHOLD_16384_SIMD_D6` (the same degree and plaintext
 * modulus with eight ciphertext moduli for multiplicative depth 6, on-chain parameter set 7).
 */
export type ThresholdBfvParamsPresetName =
  | 'INSECURE_THRESHOLD_64'
  | 'INSECURE_THRESHOLD_LBFV'
  | 'INSECURE_THRESHOLD_SIMD'
  | 'SECURE_THRESHOLD_8192'
  | 'SECURE_THRESHOLD_16384'
  | 'SECURE_THRESHOLD_16384_SIMD'
  | 'SECURE_THRESHOLD_16384_SIMD_D6'

export const ThresholdBfvParamsPresetNames = [
  'INSECURE_THRESHOLD_64',
  'INSECURE_THRESHOLD_LBFV',
  'INSECURE_THRESHOLD_SIMD',
  'SECURE_THRESHOLD_8192',
  'SECURE_THRESHOLD_16384',
  'SECURE_THRESHOLD_16384_SIMD',
  'SECURE_THRESHOLD_16384_SIMD_D6',
] as const satisfies ReadonlyArray<ThresholdBfvParamsPresetName>

export interface VerifiableEncryptionResult {
  encryptedData: Uint8Array
  proof: ProofData
}

export interface EncryptedValueAndPublicInputs {
  encryptedData: Uint8Array
  circuitInputs: CircuitInputs
}

/**
 * An l-BFV committee key's on-chain commitment, opened to its public-key rows.
 *
 * Row 0 is `pk_aggregation(pk0, crs0)`, the commitment a user-data-encryption proof exposes. A
 * circuit rebuilds the on-chain commitment from the rows and `relinearizationKey`. Each value is a
 * 32-byte big-endian field element.
 */
export interface LbfvKeyEnvelopeOpening {
  publicKeyRows: Uint8Array[]
  relinearizationKey: Uint8Array
}

export interface BfvParamSet {
  name: ThresholdBfvParamsPresetName
  params: BfvParams
}
