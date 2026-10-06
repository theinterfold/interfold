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
  it('uses v4 configuration IDs and routes secure requests to slot 2', () => {
    expect(ParamSet.Secure8192).toBe(2)
    expect(cryptoConfigIdForParamSet(ParamSet.Insecure512)).toBe('0x119c9bde7d7a31aaeef3e696ea29f8590c611d431921b6981434bd2c0fb5f7d1')
    expect(cryptoConfigIdForParamSet(ParamSet.Secure8192)).toBe('0x5ebb3432396f21cd97fca47e006b9dd38c021bf2902d3e555cf74cb91b28e44e')
    expect(() => cryptoConfigIdForParamSet(1)).toThrow('Unsupported BFV parameter set: 1')
  })

  beforeEach(() => {
    readFileSync.mockReset()
  })

  it('accepts the supported preset and committee', async () => {
    readFileSync.mockReturnValue(JSON.stringify({ preset: 'insecure-512', committee: 'minimum' }))
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
    readFileSync.mockReturnValue(JSON.stringify({ preset: 'insecure-512', committee }))
    await expect(assertSdkMinimumCircuits()).rejects.toMatchObject({ code: 'SDK_CIRCUIT_COMMITTEE_MISMATCH' })
  })

  it('rechecks the selection after another build changes the stamp', async () => {
    readFileSync.mockReturnValueOnce(JSON.stringify({ preset: 'insecure-512', committee: 'minimum' }))
    readFileSync.mockReturnValueOnce(JSON.stringify({ preset: 'secure-8192', committee: 'minimum' }))
    await assertSdkMinimumCircuits()
    await expect(assertSdkMinimumCircuits()).rejects.toMatchObject({ code: 'SDK_CIRCUIT_PRESET_MISMATCH' })
  })
})
