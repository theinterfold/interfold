// SPDX-License-Identifier: LGPL-3.0-only

import { Barretenberg, UltraHonkBackend, UltraHonkVerifierBackend, type ProofData } from '@aztec/bb.js'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { bytesToBigInt, createPublicClient, http, toHex, zeroAddress } from 'viem'
import { hardhat } from 'viem/chains'
import { InterfoldSDK } from '../../src/interfold-sdk'
import { generateProof } from '../../src/crypto/user-data-encryption'
import { insecureProofBundle } from '../../src/crypto/presets/insecure'

const circuit = insecureProofBundle.userDataEncryption

const options = { verifierTarget: 'noir-recursive-no-zk' } as const
const sdk = new InterfoldSDK({
  publicClient: createPublicClient({ chain: hardhat, transport: http() }),
  contracts: { interfold: zeroAddress, ciphernodeRegistry: zeroAddress, feeToken: zeroAddress },
  thresholdBfvParamsPresetName: 'INSECURE_THRESHOLD',
})

describe('real encryption proof', () => {
  let api: Barretenberg | undefined
  let verifier: UltraHonkVerifierBackend
  let verificationKey: Uint8Array
  let proof: ProofData
  let publicKeyCommitment: bigint
  let ciphertextCommitment: bigint

  beforeAll(async () => {
    const publicKey = await sdk.generatePublicKey()
    // Reuse one proof for positive and negative checks. Do not regenerate it per assertion.
    const { encryptedData, circuitInputs } = await sdk.encryptVectorAndGenInputs(new BigUint64Array([1n, 2n]), publicKey)
    proof = await generateProof(circuitInputs)
    publicKeyCommitment = bytesToBigInt(await sdk.computePublicKeyCommitment(publicKey))
    ciphertextCommitment = bytesToBigInt(await sdk.computeCiphertextCommitment(encryptedData))

    api = await Barretenberg.new()
    await api.initSRSChonk(2 ** 21)
    verificationKey = await new UltraHonkBackend(circuit.bytecode, api).getVerificationKey(options)
    verifier = new UltraHonkVerifierBackend(api)
  })

  afterAll(async () => {
    await api?.destroy()
  })

  it('verifies against the compiled verification key and exact PK/ciphertext bindings', async () => {
    expect(proof.publicInputs).toHaveLength(5)
    const publicInputs = proof.publicInputs.map(BigInt)
    expect(publicInputs[0]).not.toBe(0n)
    expect(publicInputs[1]).not.toBe(0n)
    expect(publicInputs.slice(2, 4)).toEqual([publicKeyCommitment, ciphertextCommitment])
    expect(publicInputs[4]).not.toBe(0n)
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
