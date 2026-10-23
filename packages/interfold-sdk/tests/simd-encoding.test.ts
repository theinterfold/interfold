// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { beforeAll, describe, expect, it } from 'vitest'

import {
  generatePublicKey,
  getThresholdBfvParamsSet,
  encryptVector,
  encryptVectorAndGenInputs,
  type VectorEncryptOptions,
} from '../src/crypto'
import { decodePlaintextCoefficients, decodePlaintextSlots } from '../src/utils'

const PRESET = 'INSECURE_THRESHOLD_SIMD'
const FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n

/** Little-endian u64 chunks, as the published plaintext output. */
const toPlaintextOutput = (coefficients: bigint[]): string =>
  '0x' + coefficients.map((value) => value.toString(16).padStart(16, '0').match(/../g)!.reverse().join('')).join('')

const modPow = (base: bigint, exponent: bigint, modulus: bigint): bigint => {
  let result = 1n
  let b = base % modulus
  for (let e = exponent; e > 0n; e >>= 1n) {
    if (e & 1n) result = (result * b) % modulus
    b = (b * b) % modulus
  }
  return result
}

describe('decodePlaintextCoefficients', () => {
  it('reads little-endian u64 chunks, with or without the 0x prefix', () => {
    const hex = '0100000000000000' + '0201000000000000' + 'ffffffffffffffff'
    const expected = [1n, 0x102n, 0xffffffffffffffffn]

    expect(decodePlaintextCoefficients(`0x${hex}`)).toEqual(expected)
    expect(decodePlaintextCoefficients(hex)).toEqual(expected)
    expect(decodePlaintextCoefficients('0x')).toEqual([])
  })

  it('rejects output that is not whole u64 chunks of hex', () => {
    expect(() => decodePlaintextCoefficients('0x01')).toThrow(/little-endian u64/)
    expect(() => decodePlaintextCoefficients('0x' + 'zz'.repeat(8))).toThrow(/little-endian u64/)
  })
})

describe('SIMD encoding', () => {
  let publicKey: Uint8Array
  let plaintextModulus: bigint
  let qModT: bigint
  let slots: BigUint64Array

  beforeAll(async () => {
    publicKey = await generatePublicKey(PRESET)
    const params = await getThresholdBfvParamsSet(PRESET)
    plaintextModulus = params.plaintextModulus
    qModT = params.moduli.reduce((product, modulus) => product * modulus, 1n) % plaintextModulus
    slots = BigUint64Array.from({ length: params.degree }, (_, i) => BigInt((i * 31 + 5) % Number(plaintextModulus)))
  })

  /** The raw plaintext polynomial the witness proves: k1 = [Q_MOD_T * m]_t, reversed, so undo both. */
  const plaintextPolynomial = (k1: Array<string | number | bigint>): bigint[] => {
    const qModTInverse = modPow(qModT, plaintextModulus - 2n, plaintextModulus)
    return k1
      .map(BigInt)
      .reverse()
      .map((coefficient) => {
        const centered = coefficient > FIELD_MODULUS / 2n ? coefficient - FIELD_MODULUS : coefficient
        const residue = ((centered % plaintextModulus) + plaintextModulus) % plaintextModulus
        return (residue * qModTInverse) % plaintextModulus
      })
  }

  it('proves the SIMD polynomial, and decodePlaintextSlots maps it back to the encrypted slots', async () => {
    const { encryptedData, circuitInputs } = await encryptVectorAndGenInputs(slots, publicKey, PRESET, { encoding: 'simd' })
    expect(encryptedData).toBeInstanceOf(Uint8Array)

    const polynomial = plaintextPolynomial(circuitInputs.k1.coefficients)
    expect(polynomial).not.toEqual(Array.from(slots))

    const output = toPlaintextOutput(polynomial)
    expect(decodePlaintextCoefficients(output)).toEqual(polynomial)
    expect(await decodePlaintextSlots(output, PRESET)).toEqual(Array.from(slots))
  })

  it('keeps the poly encoding as the default', async () => {
    const [implicit, explicit] = await Promise.all([
      encryptVectorAndGenInputs(slots, publicKey, PRESET),
      encryptVectorAndGenInputs(slots, publicKey, PRESET, { encoding: 'poly' }),
    ])

    for (const { circuitInputs } of [implicit, explicit]) {
      expect(plaintextPolynomial(circuitInputs.k1.coefficients)).toEqual(Array.from(slots))
    }
  })

  it('encrypts a SIMD vector without a proof', async () => {
    const encrypted = await encryptVector(slots, publicKey, PRESET, { encoding: 'simd' })
    const polyEncrypted = await encryptVector(slots, publicKey, PRESET)

    expect(encrypted).toBeInstanceOf(Uint8Array)
    expect(encrypted.length).toEqual(polyEncrypted.length)
  })

  it('rejects an unknown encoding', async () => {
    await expect(encryptVector(slots, publicKey, PRESET, { encoding: 'ntt' } as unknown as VectorEncryptOptions)).rejects.toThrow(
      /Unsupported vector encoding/,
    )
  })

  it('rejects SIMD for a preset whose plaintext modulus has no slots', async () => {
    const key = await generatePublicKey('INSECURE_THRESHOLD_64')

    await expect(encryptVector(new BigUint64Array([1n]), key, 'INSECURE_THRESHOLD_64', { encoding: 'simd' })).rejects.toBeDefined()
    await expect(decodePlaintextSlots(toPlaintextOutput([1n]), 'INSECURE_THRESHOLD_64')).rejects.toBeDefined()
  })
})
