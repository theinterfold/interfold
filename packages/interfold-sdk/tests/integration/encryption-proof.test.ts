// SPDX-License-Identifier: LGPL-3.0-only

import { Barretenberg, UltraHonkBackend, UltraHonkVerifierBackend, type ProofData } from '@aztec/bb.js'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { bytesToBigInt, createPublicClient, http, toHex, zeroAddress } from 'viem'
import { hardhat } from 'viem/chains'
import { InterfoldSDK } from '../../src/interfold-sdk'
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
  let innerKeyHashes: bigint[]

  beforeAll(async () => {
    const publicKey = await sdk.generatePublicKey()
    // Reuse one proof for positive and negative checks. Do not regenerate it per assertion.
    const result = await sdk.encryptVectorAndGenProof(new BigUint64Array([1n, 2n]), publicKey)
    proof = result.proof
    publicKeyCommitment = bytesToBigInt(await sdk.computePublicKeyCommitment(publicKey))
    ciphertextCommitment = bytesToBigInt(await sdk.computeCiphertextCommitment(result.encryptedData))

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
    expect(proof.publicInputs.slice(0, 4).map(BigInt)).toEqual([...innerKeyHashes, publicKeyCommitment, ciphertextCommitment])
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
