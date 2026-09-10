// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { ProofData } from '@aztec/bb.js'
import { assertSdkMinimumCircuits } from '../circuits/assert-minimum-circuits'

// Conversion to Noir types
export type Field = string | number

export interface PolynomialInput {
  coefficients: Field[]
}

/**
 * Describes the inputs to Greco circuit
 */
export interface CircuitInputs {
  pk0is: PolynomialInput[]
  pk1is: PolynomialInput[]
  ct0is: PolynomialInput[]
  ct1is: PolynomialInput[]
  u: PolynomialInput
  e0: PolynomialInput
  e1: PolynomialInput
  e0is: PolynomialInput[]
  e0_quotients: PolynomialInput[]
  k1: PolynomialInput
  r1is: PolynomialInput[]
  r2is: PolynomialInput[]
  p1is: PolynomialInput[]
  p2is: PolynomialInput[]
}

/** Load the circuit artifacts only when a caller requests a proof. */
export const generateProof = async (circuitInputs: CircuitInputs): Promise<ProofData> => {
  await assertSdkMinimumCircuits()
  const { proveUserDataEncryption } = await import('./user-data-encryption-prover')
  return proveUserDataEncryption(circuitInputs)
}
