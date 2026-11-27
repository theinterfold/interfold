// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { ProofData } from '@aztec-foundation/bb.js'
import initializeWasm from '@interfold/wasm/init'
import { compute_vk_hash } from '@interfold/wasm'
import { bytesToHex, concatHex, hexToBytes, type Hex } from 'viem'
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

/** The l-BFV presets and the polynomial degree each one proves at. Each has its own proof bundle. */
const LBFV_DEGREES = {
  INSECURE_THRESHOLD_LBFV: 128,
  SECURE_THRESHOLD_16384: 16384,
} as const

type LbfvPresetName = keyof typeof LBFV_DEGREES

const isLbfvPreset = (presetName: ThresholdBfvParamsPresetName): presetName is LbfvPresetName => presetName in LBFV_DEGREES

const loadProofBundle = async (presetName: LbfvPresetName): Promise<UserDataEncryptionProofBundle> => {
  switch (presetName) {
    case 'INSECURE_THRESHOLD_LBFV':
      return (await import('@interfold/sdk/internal/presets/insecure-lbfv')).insecureLbfvProofBundle
    case 'SECURE_THRESHOLD_16384':
      return (await import('@interfold/sdk/internal/presets/secure-16384')).secure16384ProofBundle
  }
}

/**
 * The two verification-key chains an l-BFV user-data encryption proof outputs, as public inputs 0 and 1.
 *
 * The proof's public inputs are `[ct0_vk_chain, ct1_vk_chain, pk_commitment, ct_commitment, k1_commitment]`.
 * A verifier MUST compare the first two to these values (as field elements): they bind the verification
 * key of every circuit in the proof tree, and without the comparison a proof from any circuit with the
 * same public-input shape at any level of the tree is accepted.
 */
export interface UserDataEncryptionVkChains {
  ct0: Hex
  ct1: Hex
}

const vkHash = (hashes: Hex[]): Hex => bytesToHex(compute_vk_hash(hexToBytes(concatHex(hashes))))

/**
 * Computes the expected VK chains of an l-BFV preset from the key hashes shipped with its proof bundle.
 * This mirrors `compute_ude_vk_manifest` (identity, leaf, ct, in that order) and `compute_ude_vk_chain`.
 */
export const getUserDataEncryptionVkChains = async (presetName: ThresholdBfvParamsPresetName): Promise<UserDataEncryptionVkChains> => {
  if (!isLbfvPreset(presetName)) {
    throw new Error(`The ${presetName} preset has no chunked user-data encryption proof tree.`)
  }
  await initializeWasm()
  const { vks } = await loadProofBundle(presetName)
  const chain = (top: string, identity: string, leaf: string, ct: string): Hex =>
    vkHash([top as Hex, vkHash([identity as Hex, leaf as Hex, ct as Hex])])
  return {
    ct0: chain(vks.userDataEncryptionCt0.vkHash, vks.ct0EvalChunkIdentity.vkHash, vks.ct0ChunkMain.vkHash, vks.ct0PkCtCommit.vkHash),
    ct1: chain(vks.userDataEncryptionCt1.vkHash, vks.ct1EvalChunkIdentity.vkHash, vks.ct1ChunkMain.vkHash, vks.ct1PkCtCommit.vkHash),
  }
}

/** Load the circuit artifacts only when a caller requests a proof. */
export const generateProof = async (circuitInputs: CircuitInputs, presetName?: ThresholdBfvParamsPresetName): Promise<ProofData> => {
  await assertSdkMinimumCircuits()
  const chunked = isChunkedInputs(circuitInputs)
  if (presetName !== undefined && isLbfvPreset(presetName) !== chunked) {
    throw new Error(
      `The ${presetName} preset needs the ${isLbfvPreset(presetName) ? 'l-BFV' : 'trBFV'} witness, but the witness is for the other path. ` +
        'Encrypt to the committee key the E3 published.',
    )
  }
  if (!chunked) {
    const { proveUserDataEncryption } = await import('./user-data-encryption-prover')
    return proveUserDataEncryption(circuitInputs)
  }

  const degree = circuitInputs.u.coefficients.length
  const lbfvPreset = presetName ?? (Object.keys(LBFV_DEGREES) as LbfvPresetName[]).find((candidate) => LBFV_DEGREES[candidate] === degree)
  if (lbfvPreset === undefined || !isLbfvPreset(lbfvPreset) || LBFV_DEGREES[lbfvPreset] !== degree) {
    throw new Error(
      `No user-data encryption circuit bundle supports polynomial degree ${degree} for ${presetName ?? 'an unspecified preset'}.`,
    )
  }

  const { Barretenberg, UltraHonkBackend } = await import('@aztec-foundation/bb.js')
  const { Noir } = await import('@noir-lang/noir_js')
  const { proofToFields, proveUserDataEncryptionTree } = await import('@interfold/user-data-encryption-prover')
  const { userDataEncryption, ...proofTreeCircuits } = await loadProofBundle(lbfvPreset)
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
