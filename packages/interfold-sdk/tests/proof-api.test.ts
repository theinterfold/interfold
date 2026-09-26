// SPDX-License-Identifier: LGPL-3.0-only

import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { createPublicClient, http, zeroAddress } from 'viem'
import { hardhat } from 'viem/chains'
import { InterfoldSDK } from '../src/interfold-sdk'
import { generateProof, type CircuitInputs } from '../src/crypto/user-data-encryption'

// These tests check API forwarding. The integration suite verifies real proofs.
vi.mock('../src/crypto/user-data-encryption', () => ({ generateProof: vi.fn() }))

const sdk = new InterfoldSDK({
  publicClient: createPublicClient({ chain: hardhat, transport: http() }),
  contracts: { interfold: zeroAddress, ciphernodeRegistry: zeroAddress, feeToken: zeroAddress },
  thresholdBfvParamsPresetName: 'INSECURE_THRESHOLD_512',
})

describe('proof API forwarding', () => {
  let publicKey: Uint8Array
  let expectedKeyInputs: Pick<CircuitInputs, 'pk0is' | 'pk1is'>
  let encodeCoefficient: (value: bigint) => bigint
  const proof = { proof: new Uint8Array([1, 2, 3]), publicInputs: ['0x01'] }

  beforeAll(async () => {
    publicKey = await sdk.generatePublicKey()
    expectedKeyInputs = (await sdk.encryptNumberAndGenInputs(1n, publicKey)).circuitInputs
    const params = await sdk.getThresholdBfvParamsSet()
    const fieldModulus = 21888242871839275222246405745257275088548364400416034343698204186575808495617n
    const qModT = params.moduli.reduce((product, modulus) => product * modulus, 1n) % params.plaintextModulus
    encodeCoefficient = (value) => {
      const residue = (qModT * value) % params.plaintextModulus
      const centered = residue > params.plaintextModulus / 2n ? residue - params.plaintextModulus : residue
      return (centered + fieldModulus) % fieldModulus
    }
  })

  beforeEach(() => {
    vi.mocked(generateProof).mockReset().mockResolvedValue(proof)
  })

  it.each(['number', 'vector'] as const)('forwards the %s witness and returns the proof unchanged', async (kind) => {
    const result =
      kind === 'number'
        ? await sdk.encryptNumberAndGenProof(1n, publicKey)
        : await sdk.encryptVectorAndGenProof(new BigUint64Array([1n, 2n]), publicKey)

    expect(generateProof).toHaveBeenCalledOnce()
    const [inputs] = vi.mocked(generateProof).mock.calls[0]
    expect(inputs.pk0is).toEqual(expectedKeyInputs.pk0is)
    expect(inputs.pk1is).toEqual(expectedKeyInputs.pk1is)
    const expectedPlaintext = Array<bigint>(512).fill(0n)
    expectedPlaintext[511] = encodeCoefficient(1n)
    if (kind === 'vector') expectedPlaintext[510] = encodeCoefficient(2n)
    expect(inputs.k1.coefficients.map(BigInt)).toEqual(expectedPlaintext)
    expect(inputs.ct0is).toHaveLength(2)
    expect(inputs.ct1is).toHaveLength(2)
    expect(result.proof).toBe(proof)
    expect(await sdk.computeCiphertextCommitment(result.encryptedData)).toHaveLength(32)
  })

  it.each(['number', 'vector'] as const)('propagates %s proof-generation failures', async (kind) => {
    const failure = new Error('proof generation failed')
    vi.mocked(generateProof).mockRejectedValueOnce(failure)
    const request =
      kind === 'number'
        ? sdk.encryptNumberAndGenProof(1n, publicKey)
        : sdk.encryptVectorAndGenProof(new BigUint64Array([1n, 2n]), publicKey)
    await expect(request).rejects.toBe(failure)
  })
})
