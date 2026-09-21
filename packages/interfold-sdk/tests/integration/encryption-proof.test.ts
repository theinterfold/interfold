// SPDX-License-Identifier: LGPL-3.0-only

import { Barretenberg, UltraHonkBackend, UltraHonkVerifierBackend, type ProofData } from '@aztec/bb.js'
import { CompiledCircuit, Noir } from '@noir-lang/noir_js'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { bytesToBigInt, createPublicClient, http, toHex, zeroAddress } from 'viem'
import { hardhat } from 'viem/chains'
import { InterfoldSDK } from '../../src/interfold-sdk'
import { generateProof } from '../../src/crypto/user-data-encryption'
import circuit from '../../../../circuits/bin/threshold/target/user_data_encryption.json'
import ct0Circuit from '../../../../circuits/bin/threshold/target/user_data_encryption_ct0.json'
import ct1Circuit from '../../../../circuits/bin/threshold/target/user_data_encryption_ct1.json'

const options = { verifierTarget: 'noir-recursive-no-zk' } as const
const sdk = new InterfoldSDK({
  publicClient: createPublicClient({ chain: hardhat, transport: http() }),
  contracts: { interfold: zeroAddress, ciphernodeRegistry: zeroAddress, feeToken: zeroAddress },
  thresholdBfvParamsPresetName: 'INSECURE_THRESHOLD_512',
})

describe('real encryption proof', () => {
  let api: Barretenberg | undefined
  let verifier: UltraHonkVerifierBackend
  let verificationKey: Uint8Array
  let proof: ProofData
  let publicKeyCommitment: bigint
  let ciphertextCommitment: bigint
  let k1Commitment: bigint
  let innerKeyHashes: bigint[]

  beforeAll(async () => {
    const publicKey = await sdk.generatePublicKey()
    // Reuse one proof for positive and negative checks. Do not regenerate it per assertion.
    const { encryptedData, circuitInputs } = await sdk.encryptVectorAndGenInputs(new BigUint64Array([1n, 2n]), publicKey)
    proof = await generateProof(circuitInputs)
    publicKeyCommitment = bytesToBigInt(await sdk.computePublicKeyCommitment(publicKey))
    ciphertextCommitment = bytesToBigInt(await sdk.computeCiphertextCommitment(encryptedData))

    // The outer circuit forwards `k1_commitment` from the third ct0 output. Derive the same value
    // from the `k1` witness so the assertion fails if the outer circuit forwards a different output.
    // `CircuitInputs` carries Noir structs that the `InputMap` index signature does not accept,
    // so the witness map is cast in the same way as the production prover.
    const { returnValue: ct0Outputs } = await new Noir(ct0Circuit as CompiledCircuit).execute({
      pk0is: circuitInputs.pk0is,
      ct0is: circuitInputs.ct0is,
      u: circuitInputs.u,
      e0: circuitInputs.e0,
      e0is: circuitInputs.e0is,
      e0_quotients: circuitInputs.e0_quotients,
      k1: circuitInputs.k1,
      r1is: circuitInputs.r1is,
      r2is: circuitInputs.r2is,
    } as any)
    k1Commitment = BigInt((ct0Outputs as string[])[2])

    api = await Barretenberg.new()
    await api.initSRSChonk(2 ** 21)
    verificationKey = await new UltraHonkBackend(circuit.bytecode, api).getVerificationKey(options)
    verifier = new UltraHonkVerifierBackend(api)
    innerKeyHashes = []
    for (const innerCircuit of [ct0Circuit, ct1Circuit]) {
      const artifacts = await new UltraHonkBackend(innerCircuit.bytecode, api).generateRecursiveProofArtifacts(new Uint8Array(), 0, options)
      innerKeyHashes.push(BigInt(artifacts.vkHash))
    }
  })

  afterAll(async () => {
    await api?.destroy()
  })

  it('verifies against the compiled verification key and exact PK/ciphertext bindings', async () => {
    expect(proof.publicInputs).toHaveLength(5)
    expect(proof.publicInputs.map(BigInt)).toEqual([...innerKeyHashes, publicKeyCommitment, ciphertextCommitment, k1Commitment])
    expect(await verifier.verifyProof({ ...proof, verificationKey }, options)).toBe(true)
  })

  it.each([0, 1, 2, 3, 4])('rejects an altered public input at position %i', async (index) => {
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
