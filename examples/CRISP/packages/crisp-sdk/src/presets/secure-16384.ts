// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// The secure-16384 preset-bound circuits, published as a separate entry point.

import type { CircuitBundle, CircuitPreset } from '../circuits'
import type { CompiledCircuit } from '@noir-lang/noir_js'

import crisp from '../../../../circuits/dist/secure-16384/crisp.json'
import crispOnchain from '../../../../circuits/dist/secure-16384/crisp_onchain.json'
import userDataEncryptionCt0 from '../../../../circuits/dist/secure-16384/user_data_encryption_ct0.json'
import userDataEncryptionCt1 from '../../../../circuits/dist/secure-16384/user_data_encryption_ct1.json'

export const preset: CircuitPreset = 'secure-16384'

/** The secure-16384 circuits, ready for `setCircuits()`. */
export const loadCircuits = async (): Promise<CircuitBundle> => ({
  preset,
  crisp: crisp as CompiledCircuit,
  crispOnchain: crispOnchain as CompiledCircuit,
  userDataEncryptionCt0: userDataEncryptionCt0 as CompiledCircuit,
  userDataEncryptionCt1: userDataEncryptionCt1 as CompiledCircuit,
})
