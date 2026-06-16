// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { Barretenberg, UltraHonkBackend, type ProofData } from '@aztec/bb.js'
import userDataEncryptionCt0Circuit from '../../../../circuits/bin/threshold/target/user_data_encryption_ct0.json'
import userDataEncryptionCt1Circuit from '../../../../circuits/bin/threshold/target/user_data_encryption_ct1.json'
import userDataEncryptionCircuit from '../../../../circuits/bin/threshold/target/user_data_encryption.json'
import { CompiledCircuit, Noir } from '@noir-lang/noir_js'
import { assertSdkMinimumCircuits } from '../circuits/assert-minimum-circuits'
import { proofToFields } from '../utils'

assertSdkMinimumCircuits()

// Conversion to Noir types
export type Field = string

/**
 * Describes the inputs to Greco circuit
 */
export interface CircuitInputs {
  pk0is: string[][]
  pk1is: string[][]
  ct0is: string[][]
  ct1is: string[][]
  u: string[]
  e0: string[]
  e1: string[]
  e0is: string[][]
  e0_quotients: string[][]
  k1: string[]
  r1is: string[][]
  r2is: string[][]
  p1is: string[][]
  p2is: string[][]
  pk_commitment: string
}

/**
 * Generate a proof for a given circuit and circuit inputs
 * @dev Defaults to the UltraHonkBackend
 * @param circuitInputs - The circuit inputs
 * @param circuit - The circuit
 * @returns The proof
 */
export const generateProof = async (circuitInputs: CircuitInputs): Promise<ProofData> => {
  const api = await Barretenberg.new()

  try {
    await api.initSRSChonk(2 ** 21) // fold circuit needs 2^21 points; default is 2^20

    const { witness: userDataEncryptionCt0Witness } = await executeCircuit(userDataEncryptionCt0Circuit as CompiledCircuit, {
      pk0is: circuitInputs.pk0is,
      ct0is: circuitInputs.ct0is,
      u: circuitInputs.u,
      e0: circuitInputs.e0,
      e0is: circuitInputs.e0is,
      e0_quotients: circuitInputs.e0_quotients,
      k1: circuitInputs.k1,
      r1is: circuitInputs.r1is,
      r2is: circuitInputs.r2is,
    })
    const { witness: userDataEncryptionCt1Witness } = await executeCircuit(userDataEncryptionCt1Circuit as CompiledCircuit, {
      pk1is: circuitInputs.pk1is,
      ct1is: circuitInputs.ct1is,
      u: circuitInputs.u,
      e1: circuitInputs.e1,
      p1is: circuitInputs.p1is,
      p2is: circuitInputs.p2is,
    })

    const userDataEncryptionCt0Backend = new UltraHonkBackend((userDataEncryptionCt0Circuit as CompiledCircuit).bytecode, api)
    const userDataEncryptionCt1Backend = new UltraHonkBackend((userDataEncryptionCt1Circuit as CompiledCircuit).bytecode, api)

    const { proof: userDataEncryptionCt0Proof, publicInputs: userDataEncryptionCt0PublicInputs } =
      await userDataEncryptionCt0Backend.generateProof(userDataEncryptionCt0Witness, {
        verifierTarget: 'noir-recursive-no-zk',
      })
    const { proof: userDataEncryptionCt1Proof, publicInputs: userDataEncryptionCt1PublicInputs } =
      await userDataEncryptionCt1Backend.generateProof(userDataEncryptionCt1Witness, {
        verifierTarget: 'noir-recursive-no-zk',
      })

    const userDataEncryptionCt0Artifacts = await userDataEncryptionCt0Backend.generateRecursiveProofArtifacts(
      userDataEncryptionCt0Proof,
      userDataEncryptionCt0PublicInputs.length,
      {
        verifierTarget: 'noir-recursive-no-zk',
      },
    )
    const userDataEncryptionCt1Artifacts = await userDataEncryptionCt1Backend.generateRecursiveProofArtifacts(
      userDataEncryptionCt1Proof,
      userDataEncryptionCt1PublicInputs.length,
      {
        verifierTarget: 'noir-recursive-no-zk',
      },
    )

    const { witness: userDataEncryptionWitness } = await executeCircuit(userDataEncryptionCircuit as CompiledCircuit, {
      ct0_verification_key: userDataEncryptionCt0Artifacts.vkAsFields,
      ct0_proof: proofToFields(userDataEncryptionCt0Proof),
      ct0_public_inputs: userDataEncryptionCt0PublicInputs,
      ct0_key_hash: userDataEncryptionCt0Artifacts.vkHash,
      ct1_verification_key: userDataEncryptionCt1Artifacts.vkAsFields,
      ct1_proof: proofToFields(userDataEncryptionCt1Proof),
      ct1_public_inputs: userDataEncryptionCt1PublicInputs,
      ct1_key_hash: userDataEncryptionCt1Artifacts.vkHash,
    })

    const userDataEncryptionBackend = new UltraHonkBackend((userDataEncryptionCircuit as CompiledCircuit).bytecode, api)

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
