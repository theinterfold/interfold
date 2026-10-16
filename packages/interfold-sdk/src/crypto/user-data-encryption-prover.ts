// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { Barretenberg, UltraHonkBackend, type ProofData } from '@aztec-foundation/bb.js'
import userDataEncryptionCircuit from '../../../../circuits/bin/threshold/target/user_data_encryption.json'
import { CompiledCircuit, Noir } from '@noir-lang/noir_js'

import type { TrbfvCircuitInputs } from './user-data-encryption'

export const proveUserDataEncryption = async (circuitInputs: TrbfvCircuitInputs): Promise<ProofData> => {
  // The circuit needs 2^21 SRS points. Pass the size to `new`: on the WASM backend that
  // browsers use, a later `initSRSChonk` call does not enlarge the SRS that `new` loads.
  const api = await Barretenberg.new({ srsSize: 2 ** 21 })

  try {
    // One circuit proves both ciphertext legs over a shared `u`. It hard-codes the CRS as `pk1`, so
    // the key's second component is not an input.
    const { witness: userDataEncryptionWitness } = await executeCircuit(userDataEncryptionCircuit as CompiledCircuit, {
      pk0is: circuitInputs.pk0is,
      ct0is: circuitInputs.ct0is,
      ct1is: circuitInputs.ct1is,
      u: circuitInputs.u,
      e0: circuitInputs.e0,
      e1: circuitInputs.e1,
      k1: circuitInputs.k1,
      r: circuitInputs.r,
      r_ct1: circuitInputs.r_ct1,
    })

    const userDataEncryptionBackend = new UltraHonkBackend((userDataEncryptionCircuit as CompiledCircuit).bytecode, api)

    return await userDataEncryptionBackend.generateProof(userDataEncryptionWitness, {
      verifierTarget: 'noir-recursive-no-zk',
    })
  } finally {
    // `destroy` returns a promise; await it so the proof settles after cleanup completes.
    await api.destroy()
  }
}

const executeCircuit = async (circuit: CompiledCircuit, inputs: any): Promise<{ witness: Uint8Array; returnValue: any }> => {
  const noir = new Noir(circuit as CompiledCircuit)

  return noir.execute(inputs)
}
