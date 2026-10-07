// SPDX-License-Identifier: LGPL-3.0-only

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
  it('uses the active configuration IDs and routes secure requests to slots 2 and 3', () => {
    expect(ParamSet.Secure8192).toBe(2)
    expect(ParamSet.Secure16384).toBe(3)
    expect(cryptoConfigIdForParamSet(ParamSet.Insecure)).toBe('0x7317c190ccb1dccfa505bf5b9b923e341905f6675c16f958e0a7d853795517a5')
    expect(cryptoConfigIdForParamSet(ParamSet.Secure8192)).toBe('0xac5490c59e158cbb104642bba0ab7b3fd11ca49dd4bb05ce7bec8089ce3c8c31')
    expect(cryptoConfigIdForParamSet(ParamSet.Secure16384)).toBe('0xde3c303973a0bf2b841cd0e7266ae68a7e48f8b271ffd629b245485e52dc8cd8')
    expect(() => cryptoConfigIdForParamSet(1)).toThrow('Unsupported BFV parameter set: 1')
  })

  beforeEach(() => {
    readFileSync.mockReset()
  })

  it('accepts the supported preset and committee', async () => {
    readFileSync.mockReturnValue(JSON.stringify({ preset: 'insecure', committee: 'minimum' }))
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
    readFileSync.mockReturnValue(JSON.stringify({ preset: 'insecure', committee }))
    await expect(assertSdkMinimumCircuits()).rejects.toMatchObject({ code: 'SDK_CIRCUIT_COMMITTEE_MISMATCH' })
  })

  it('accepts a supported secure active preset after a separate circuit build', async () => {
    readFileSync.mockReturnValueOnce(JSON.stringify({ preset: 'insecure', committee: 'minimum' }))
    readFileSync.mockReturnValueOnce(JSON.stringify({ preset: 'secure-8192', committee: 'minimum' }))
    await assertSdkMinimumCircuits()
    await expect(assertSdkMinimumCircuits()).resolves.toBeUndefined()
  })

  it('rejects an unsupported active preset', async () => {
    readFileSync.mockReturnValue(JSON.stringify({ preset: 'unknown', committee: 'minimum' }))
    await expect(assertSdkMinimumCircuits()).rejects.toMatchObject({ code: 'SDK_CIRCUIT_PRESET_MISMATCH' })
  })
})
