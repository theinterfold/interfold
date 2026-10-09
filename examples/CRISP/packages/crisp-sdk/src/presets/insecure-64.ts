// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// The insecure-64 (N=64, L=3) preset-bound circuits, published as a separate entry point.
//
// Kept out of the main entry so a consumer's bundler pulls one preset rather than both. The
// artifacts are staged by scripts/stage-preset-artifacts.mjs; see src/circuits.ts for why the
// aggregation circuits are not among them.

import type { CircuitBundle, CircuitPreset } from '../circuits'
import type { CompiledCircuit } from '@noir-lang/noir_js'

import crisp from '../../../../circuits/dist/insecure-64/crisp.json'
import crispOnchain from '../../../../circuits/dist/insecure-64/crisp_onchain.json'
import userDataEncryptionCt0 from '../../../../circuits/dist/insecure-64/user_data_encryption_ct0.json'
import userDataEncryptionCt1 from '../../../../circuits/dist/insecure-64/user_data_encryption_ct1.json'

export const preset: CircuitPreset = 'insecure-64'

/**
 * The insecure-64 (N=64, L=3) circuits, ready for `setCircuits()`.
 *
 * Asynchronous because the artifacts are inlined today but need not stay that way: the secure set
 * is large enough that a consumer may want it fetched on demand, and that change belongs inside
 * this function rather than in every caller.
 */
export const loadCircuits = async (): Promise<CircuitBundle> => ({
  preset,
  crisp: crisp as CompiledCircuit,
  crispOnchain: crispOnchain as CompiledCircuit,
  userDataEncryptionCt0: userDataEncryptionCt0 as CompiledCircuit,
  userDataEncryptionCt1: userDataEncryptionCt1 as CompiledCircuit,
})
