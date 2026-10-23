// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { ProofData } from '@aztec-foundation/bb.js'
import { assertSdkMinimumCircuits } from '../circuits/assert-minimum-circuits'
import type { UserDataEncryptionProofBundle } from './presets/types'
import type { ThresholdBfvParamsPresetName } from './types'

// Conversion to Noir types
export type Field = string | number

export interface PolynomialInput {
  coefficients: Field[]
}

/** Inputs of the trBFV path's user-data encryption circuit (`user_data_encryption`). */
export interface TrbfvCircuitInputs {
  pk0is: PolynomialInput[]
  ct0is: PolynomialInput[]
  ct1is: PolynomialInput[]
  u: PolynomialInput
  e0: PolynomialInput
  e1: PolynomialInput
  k1: PolynomialInput
  r: PolynomialInput[]
  r_ct1: PolynomialInput[]
}

/** Inputs of the l-BFV path's chunked user-data encryption proof tree. */
export interface ChunkedCircuitInputs {
  pk0is: PolynomialInput[]
  pk1is: PolynomialInput[]
  ct0is: PolynomialInput[]
  ct1is: PolynomialInput[]
  u: PolynomialInput
  e0: PolynomialInput
  e1: PolynomialInput
  k1: PolynomialInput
  r1is: PolynomialInput[]
  p1is: PolynomialInput[]
  pk_commitment: string
  /** `commit(pk0is)`, hashed into the ct0 leaf's challenge. */
  pk0_commitment: string
  /** `commit(pk1is)`, hashed into the ct1 leaf's challenge. */
  pk1_commitment: string
  /** `commit(ct0is)`, hashed into the ct0 leaf's challenge. */
  ct0_commitment: string
  /** `commit(ct1is)`, hashed into the ct1 leaf's challenge. */
  ct1_commitment: string
}

/**
 * Describes the inputs to the user-data encryption proof. The encryption client builds the trBFV
 * form for a plain committee key and the chunked form for an l-BFV key envelope.
 */
export type CircuitInputs = TrbfvCircuitInputs | ChunkedCircuitInputs

const isChunkedInputs = (inputs: CircuitInputs): inputs is ChunkedCircuitInputs => 'r1is' in inputs

/** Presets on the l-BFV path. Their user-data encryption proofs use the chunked proof tree. */
const LBFV_PRESETS: ReadonlySet<ThresholdBfvParamsPresetName> = new Set([
  'INSECURE_THRESHOLD_LBFV',
  'INSECURE_THRESHOLD_SIMD',
  'SECURE_THRESHOLD_16384',
])

/** Chunked proof bundles by polynomial degree. */
const CHUNKED_BUNDLE_DEGREES = {
  insecure: 128,
  'insecure-simd': 128,
  'secure-8192': 8192,
  'secure-16384': 16384,
} as const

type ChunkedBundleName = keyof typeof CHUNKED_BUNDLE_DEGREES

/**
 * The bundle of each l-BFV preset. `insecure` and `insecure-simd` share degree 128 but differ in
 * the plaintext modulus, so a preset must pick its bundle by name, not by degree.
 */
const CHUNKED_BUNDLE_BY_PRESET: Partial<Record<ThresholdBfvParamsPresetName, ChunkedBundleName>> = {
  INSECURE_THRESHOLD_LBFV: 'insecure',
  INSECURE_THRESHOLD_SIMD: 'insecure-simd',
  SECURE_THRESHOLD_16384: 'secure-16384',
}

const loadProofBundle = async (bundle: ChunkedBundleName): Promise<UserDataEncryptionProofBundle> => {
  switch (bundle) {
    case 'insecure':
      return (await import('@interfold/sdk/internal/presets/insecure')).insecureProofBundle
    case 'insecure-simd':
      return (await import('@interfold/sdk/internal/presets/insecure-simd')).insecureSimdProofBundle
    case 'secure-8192':
      return (await import('@interfold/sdk/internal/presets/secure-8192')).secure8192ProofBundle
    case 'secure-16384':
      return (await import('@interfold/sdk/internal/presets/secure-16384')).secure16384ProofBundle
  }
}

/** Load the circuit artifacts only when a caller requests a proof. */
export const generateProof = async (circuitInputs: CircuitInputs, presetName?: ThresholdBfvParamsPresetName): Promise<ProofData> => {
  await assertSdkMinimumCircuits()
  const chunked = isChunkedInputs(circuitInputs)
  if (presetName !== undefined && LBFV_PRESETS.has(presetName) !== chunked) {
    throw new Error(
      `The ${presetName} preset needs the ${LBFV_PRESETS.has(presetName) ? 'l-BFV' : 'trBFV'} witness, but the witness is for the other path. ` +
        'Encrypt to the committee key the E3 published.',
    )
  }
  if (!chunked) {
    const { proveUserDataEncryption } = await import('./user-data-encryption-prover')
    return proveUserDataEncryption(circuitInputs)
  }

  // Without a preset the degree selects the bundle; degree 128 then resolves to the insecure bundle.
  const degree = circuitInputs.u.coefficients.length
  const bundleName =
    (presetName === undefined ? undefined : CHUNKED_BUNDLE_BY_PRESET[presetName]) ??
    (Object.entries(CHUNKED_BUNDLE_DEGREES) as [ChunkedBundleName, number][]).find(([, bundleDegree]) => bundleDegree === degree)?.[0]
  if (bundleName === undefined) {
    throw new Error(`No user-data encryption circuit bundle supports polynomial degree ${degree}.`)
  }

  const { Barretenberg, UltraHonkBackend } = await import('@aztec-foundation/bb.js')
  const { Noir } = await import('@noir-lang/noir_js')
  const { proveUserDataEncryptionTree } = await import('@interfold/user-data-encryption-prover')
  const { proofToFields } = await import('../utils')
  const { userDataEncryption, ...proofTreeCircuits } = await loadProofBundle(bundleName)
  // Size the SRS at creation; see `proveUserDataEncryption`.
  const api = await Barretenberg.new({ srsSize: 2 ** 21 })
  try {
    const { ct0, ct1 } = await proveUserDataEncryptionTree(api, proofTreeCircuits, circuitInputs)
    const noir = new Noir(userDataEncryption)
    const { witness } = await noir.execute({
      ct0_verification_key: ct0.vkAsFields,
      ct0_proof: proofToFields(ct0.proof),
      ct0_public_inputs: ct0.publicInputs,
      ct0_key_hash: ct0.vkHash,
      ct1_verification_key: ct1.vkAsFields,
      ct1_proof: proofToFields(ct1.proof),
      ct1_public_inputs: ct1.publicInputs,
      ct1_key_hash: ct1.vkHash,
    })
    const backend = new UltraHonkBackend(userDataEncryption.bytecode, api)
    return await backend.generateProof(witness, { verifierTarget: 'noir-recursive-no-zk' })
  } finally {
    await api.destroy()
  }
}
