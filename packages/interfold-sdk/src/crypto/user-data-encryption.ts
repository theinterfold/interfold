// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { Barretenberg, UltraHonkBackend, type ProofData } from '@aztec/bb.js'
import { proveUserDataEncryptionTree } from '@interfold/user-data-encryption-prover'
import { CompiledCircuit, Noir } from '@noir-lang/noir_js'
import { assertSdkMinimumCircuits } from '../circuits/assert-minimum-circuits'
import { proofToFields } from '../utils'
import type { UserDataEncryptionProofBundle } from './presets/types'
import type { ThresholdBfvParamsPresetName } from './types'

assertSdkMinimumCircuits()

// Conversion to Noir types
export type Field = string
export type NoirCoefficient = string | number
export type NoirPolynomial = { coefficients: NoirCoefficient[] }
export type NoirCrtPolynomial = NoirPolynomial[]

/**
 * Describes the inputs to Greco circuit
 */
export interface CircuitInputs {
  pk0is: NoirCrtPolynomial
  pk1is: NoirCrtPolynomial
  ct0is: NoirCrtPolynomial
  ct1is: NoirCrtPolynomial
  u: NoirPolynomial
  e0: NoirPolynomial
  e1: NoirPolynomial
  e0is: NoirCrtPolynomial
  e0_quotients: NoirCrtPolynomial
  k1: NoirPolynomial
  r1is: NoirCrtPolynomial
  r2is: NoirCrtPolynomial
  p1is: NoirCrtPolynomial
  p2is: NoirCrtPolynomial
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

const resolveProofBundle = async (
  circuitInputs: CircuitInputs,
  presetName?: ThresholdBfvParamsPresetName,
): Promise<UserDataEncryptionProofBundle> => {
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

  return loadProofBundle(presetName ?? inferredPreset)
}

/**
 * Generate a proof for a given circuit and circuit inputs
 * @dev Defaults to the UltraHonkBackend
 * @param circuitInputs - The circuit inputs
 * @param presetName - The BFV preset. When omitted, the function selects it from the witness degree.
 * @returns The proof
 */
export const generateProof = async (circuitInputs: CircuitInputs, presetName?: ThresholdBfvParamsPresetName): Promise<ProofData> => {
  const { userDataEncryption, ...proofTreeCircuits } = await resolveProofBundle(circuitInputs, presetName)
  const api = await Barretenberg.new()

  try {
    await api.initSRSChonk(2 ** 21) // fold circuit needs 2^21 points; default is 2^20

    const { ct0, ct1 } = await proveUserDataEncryptionTree(api, proofTreeCircuits, circuitInputs)

    const { witness: userDataEncryptionWitness } = await executeCircuit(userDataEncryption, {
      ct0_verification_key: ct0.vkAsFields,
      ct0_proof: proofToFields(ct0.proof),
      ct0_public_inputs: ct0.publicInputs,
      ct0_key_hash: ct0.vkHash,
      ct1_verification_key: ct1.vkAsFields,
      ct1_proof: proofToFields(ct1.proof),
      ct1_public_inputs: ct1.publicInputs,
      ct1_key_hash: ct1.vkHash,
    })

    const userDataEncryptionBackend = new UltraHonkBackend(userDataEncryption.bytecode, api)

    return await userDataEncryptionBackend.generateProof(userDataEncryptionWitness, {
      verifierTarget: 'noir-recursive-no-zk',
    })
  } finally {
    api.destroy()
  }
}

const executeCircuit = async (circuit: CompiledCircuit, inputs: any): Promise<{ witness: Uint8Array; returnValue: any }> => {
  const noir = new Noir(circuit as CompiledCircuit)

  return noir.execute(inputs)
}
