// SPDX-License-Identifier: LGPL-3.0-only

import { Barretenberg, UltraHonkBackend, UltraHonkVerifierBackend, type ProofData } from '@aztec-foundation/bb.js'
import { CompiledCircuit, Noir } from '@noir-lang/noir_js'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { bytesToBigInt, createPublicClient, http, toHex, zeroAddress } from 'viem'
import { hardhat } from 'viem/chains'
import { InterfoldSDK } from '../../src/interfold-sdk'
import { generateProof } from '../../src/crypto/user-data-encryption'
import circuit from '../../../../circuits/bin/threshold/target/user_data_encryption.json'

const options = { verifierTarget: 'noir-recursive-no-zk' } as const
const sdk = new InterfoldSDK({
  publicClient: createPublicClient({ chain: hardhat, transport: http() }),
  contracts: { interfold: zeroAddress, ciphernodeRegistry: zeroAddress, feeToken: zeroAddress },
  thresholdBfvParamsPresetName: 'INSECURE_THRESHOLD_64',
})

describe('real encryption proof', () => {
  let api: Barretenberg | undefined
  let verifier: UltraHonkVerifierBackend
  let verificationKey: Uint8Array
  let proof: ProofData
  let publicKeyCommitment: bigint
  let ciphertextCommitment: bigint
  let k1Commitment: bigint

  beforeAll(async () => {
    const publicKey = await sdk.generatePublicKey()
    // Reuse one proof for positive and negative checks. Do not regenerate it per assertion.
    const { encryptedData, circuitInputs } = await sdk.encryptVectorAndGenInputs(new BigUint64Array([1n, 2n]), publicKey)
    // Prove on WASM, the backend that browsers use: bb.js falls back to WASM in Node when
    // `BB_BINARY_PATH` names a missing binary. The verifier below keeps the default backend.
    vi.stubEnv('BB_BINARY_PATH', '/nonexistent/bb')
    try {
      proof = await generateProof(circuitInputs)
    } finally {
      vi.unstubAllEnvs()
    }
    publicKeyCommitment = bytesToBigInt(await sdk.computePublicKeyCommitment(publicKey))
    ciphertextCommitment = bytesToBigInt(await sdk.computeCiphertextCommitment(encryptedData))

    // The circuit returns `k1_commitment` itself; that it is ct0's commitment of `k1` is checked by
    // the Noir test `both_legs_over_one_u_are_accepted`. Execute the circuit here, so the assertion
    // fails if the proof's public inputs are not the circuit's outputs. `CircuitInputs` carries Noir
    // structs that the `InputMap` index signature does not accept, so the witness map is cast in
    // the same way as the production prover.
    const { returnValue: outputs } = await new Noir(circuit as CompiledCircuit).execute(circuitInputs as any)
    k1Commitment = BigInt((outputs as string[])[2])

    api = await Barretenberg.new({ srsSize: 2 ** 21 })
    verificationKey = await new UltraHonkBackend(circuit.bytecode, api).getVerificationKey(options)
    verifier = new UltraHonkVerifierBackend(api)
  })

  afterAll(async () => {
    await api?.destroy()
  })

  it('verifies against the compiled verification key and exact PK/ciphertext bindings', async () => {
    expect(proof.publicInputs).toHaveLength(3)
    expect(proof.publicInputs.map(BigInt)).toEqual([publicKeyCommitment, ciphertextCommitment, k1Commitment])
    expect(await verifier.verifyProof({ ...proof, verificationKey }, options)).toBe(true)
  })

  it.each([0, 1, 2])('rejects an altered public input at position %i', async (index) => {
    const publicInputs = [...proof.publicInputs]
    publicInputs[index] = toHex(BigInt(publicInputs[index]) ^ 1n, { size: 32 })
    expect(await verifier.verifyProof({ ...proof, publicInputs, verificationKey }, options)).toBe(false)
  })

  it('rejects altered proof contents', async () => {
    const altered = proof.proof.slice()
    altered[altered.length - 1] ^= 1
    await expect(verifier.verifyProof({ ...proof, proof: altered, verificationKey }, options)).rejects.toThrow(
      'Deserialized point is not on the curve',
    )
  })
})
