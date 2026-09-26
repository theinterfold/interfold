// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { ProofData } from '@aztec/bb.js'
import { assertSdkMinimumCircuits } from '../circuits/assert-minimum-circuits'
import type { UserDataEncryptionProofBundle } from './presets/types'
import type { ThresholdBfvParamsPresetName } from './types'

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
  pk_commitment: string
}

const PRESET_DEGREES: Record<ThresholdBfvParamsPresetName, number> = {
  INSECURE_THRESHOLD: 128,
  SECURE_THRESHOLD_8192: 8192,
  SECURE_THRESHOLD_16384: 16384,
}

const loadProofBundle = async (presetName: ThresholdBfvParamsPresetName): Promise<UserDataEncryptionProofBundle> => {
  switch (presetName) {
    case 'INSECURE_THRESHOLD':
      return (await import('@interfold/sdk/internal/presets/insecure')).insecureProofBundle
    case 'SECURE_THRESHOLD_8192':
      return (await import('@interfold/sdk/internal/presets/secure-8192')).secure8192ProofBundle
    case 'SECURE_THRESHOLD_16384':
      return (await import('@interfold/sdk/internal/presets/secure-16384')).secure16384ProofBundle
  }
}

/** Load the circuit artifacts only when a caller requests a proof. */
export const generateProof = async (circuitInputs: CircuitInputs, presetName?: ThresholdBfvParamsPresetName): Promise<ProofData> => {
  await assertSdkMinimumCircuits()
  const degree = circuitInputs.u.coefficients.length
  const inferredPreset = (Object.entries(PRESET_DEGREES) as [ThresholdBfvParamsPresetName, number][]).find(
    ([, presetDegree]) => presetDegree === degree,
  )?.[0]
  if (inferredPreset === undefined) {
    throw new Error(`No user-data encryption circuit bundle supports polynomial degree ${degree}.`)
  }
  if (presetName !== undefined && presetName !== inferredPreset) {
    throw new Error(`The ${presetName} proof bundle requires degree ${PRESET_DEGREES[presetName]}, but the witness has degree ${degree}.`)
  }

  const { Barretenberg, UltraHonkBackend } = await import('@aztec/bb.js')
  const { Noir } = await import('@noir-lang/noir_js')
  const { proveUserDataEncryptionTree } = await import('@interfold/user-data-encryption-prover')
  const { proofToFields } = await import('../utils')
  const { userDataEncryption, ...proofTreeCircuits } = await loadProofBundle(presetName ?? inferredPreset)
  const api = await Barretenberg.new()
  try {
    await api.initSRSChonk(2 ** 21)
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
