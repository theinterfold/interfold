// SPDX-License-Identifier: LGPL-3.0-only

import { readFileSync as readFixture } from 'node:fs'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { assertSdkMinimumCircuits } from '../src/circuits/assert-minimum-circuits'
import { ParamSet } from '../src/contracts/types'
import { cryptoConfigIdForParamSet } from '../src/utils'

const { readFileSync } = vi.hoisted(() => ({ readFileSync: vi.fn() }))
vi.mock('node:fs', async () => {
  const fs = await vi.importActual<typeof import('node:fs')>('node:fs')
  return {
    ...fs,
    readFileSync: (...args: Parameters<typeof fs.readFileSync>) =>
      args[0].toString().endsWith('.active-preset.json') ? readFileSync(...args) : fs.readFileSync(...args),
  }
})

describe('SDK circuit selection', () => {
  it('uses current configuration IDs and the current secure registry entry', () => {
    const fixture = JSON.parse(readFixture(new URL('../../../crates/fhe-params/tests/fixtures/bfv_protocol.json', import.meta.url), 'utf8'))
    expect(ParamSet.Secure8192).toBe(fixture.vectors.find((vector: { name: string }) => vector.name === 'current-secure').paramSet)
    for (const vector of fixture.vectors.filter((vector: { preset: string | null }) => vector.preset !== null)) {
      expect(cryptoConfigIdForParamSet(vector.paramSet)).toBe(vector.cryptoConfigId)
    }
    expect(() => cryptoConfigIdForParamSet(1)).toThrow('Unsupported BFV parameter set: 1')
    expect(() => cryptoConfigIdForParamSet(1)).toThrowError(expect.objectContaining({ code: 'UNSUPPORTED_CRYPTO_CONFIG' }))
  })

  beforeEach(() => {
    readFileSync.mockReset()
  })

  it('accepts the supported preset and committee', async () => {
    readFileSync.mockReturnValue(JSON.stringify({ preset: 'insecure-64', committee: 'minimum' }))
    await expect(assertSdkMinimumCircuits()).resolves.toBeUndefined()
  })

  it('rejects missing artifacts through the awaited request', async () => {
    readFileSync.mockImplementation(() => {
      throw new Error('ENOENT')
    })
    await expect(assertSdkMinimumCircuits()).rejects.toMatchObject({ code: 'SDK_CIRCUIT_STAMP_MISSING' })
  })

  it.each(['{', 'null', '[]', '"invalid"'])('rejects invalid stamp %s', async (stamp) => {
    readFileSync.mockReturnValue(stamp)
    await expect(assertSdkMinimumCircuits()).rejects.toMatchObject({ code: 'SDK_CIRCUIT_STAMP_INVALID' })
  })

  it.each(['micro', 'small', undefined])('rejects committee %s', async (committee) => {
    readFileSync.mockReturnValue(JSON.stringify({ preset: 'insecure-64', committee }))
    await expect(assertSdkMinimumCircuits()).rejects.toMatchObject({ code: 'SDK_CIRCUIT_COMMITTEE_MISMATCH' })
  })

  it('rechecks the selection after another build changes the stamp', async () => {
    readFileSync.mockReturnValueOnce(JSON.stringify({ preset: 'insecure-64', committee: 'minimum' }))
    readFileSync.mockReturnValueOnce(JSON.stringify({ preset: 'secure-8192', committee: 'minimum' }))
    await assertSdkMinimumCircuits()
    await expect(assertSdkMinimumCircuits()).rejects.toMatchObject({ code: 'SDK_CIRCUIT_PRESET_MISMATCH' })
  })
})
