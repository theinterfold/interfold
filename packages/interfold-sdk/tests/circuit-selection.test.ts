// SPDX-License-Identifier: LGPL-3.0-only

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { assertSdkMinimumCircuits } from '../src/circuits/assert-minimum-circuits'
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
  it('uses v2 configuration IDs for both BFV parameter sets', () => {
    expect(cryptoConfigIdForParamSet(0)).toBe('0x19921c8c12f93c3013be57d0859f4ddcdb4464ac856a0c62be1ad617fbbd2e7d')
    expect(cryptoConfigIdForParamSet(1)).toBe('0x38445056db875658295a1531cc5e81ceb73d4f210e2d969465292204fa547446')
    expect(() => cryptoConfigIdForParamSet(2)).toThrow('Unsupported BFV parameter set: 2')
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
