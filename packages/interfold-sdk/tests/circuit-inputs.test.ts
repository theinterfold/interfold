// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { beforeAll, describe, expect, it } from 'vitest'
import { encryptNumberAndGenInputs, encryptVectorAndGenInputs, generatePublicKey, parseCircuitInputs } from '../src/crypto/encrypt'

const leaves = (value: unknown): unknown[] => (typeof value === 'object' && value !== null ? Object.values(value).flatMap(leaves) : [value])

describe('verifiable encryption circuit inputs', () => {
  // Secure presets have 60-bit moduli, so their witnesses hold integers above 2^53.
  const preset = 'SECURE_THRESHOLD_8192'
  let publicKey: Uint8Array

  beforeAll(async () => {
    publicKey = await generatePublicKey(preset)
  })

  it.each([
    ['number', () => encryptNumberAndGenInputs(1n, publicKey, preset)],
    ['vector', () => encryptVectorAndGenInputs(new BigUint64Array([1n, 2n]), publicKey, preset)],
  ] as const)('returns %s witness values that noir_js accepts', async (_, encrypt) => {
    const { circuitInputs } = await encrypt()

    // noir_js rejects numbers above 2^53 because JSON.parse may already have rounded them.
    const unsafe = leaves(circuitInputs).filter((value) => typeof value === 'number' && !Number.isSafeInteger(value))
    expect(unsafe.length).toBe(0)
  })

  it('keeps every digit of witness values above 2^53', () => {
    expect(parseCircuitInputs('{"k1":{"coefficients":[9007199254740993,7,"9007199254740993"]}}')).toEqual({
      k1: { coefficients: ['9007199254740993', 7, '9007199254740993'] },
    })
  })
})
