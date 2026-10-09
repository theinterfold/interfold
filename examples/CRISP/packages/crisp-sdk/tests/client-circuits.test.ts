// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { afterEach, describe, expect, it, vi } from 'vitest'

const sdkState = vi.hoisted(() => ({
  current: null as string | null,
  loads: [] as string[],
}))

vi.mock('@crisp-e3/sdk', () => ({
  registeredPreset: () => sdkState.current,
  setCircuits: (bundle: { preset: string }) => {
    sdkState.current = bundle.preset
  },
}))

vi.mock('@crisp-e3/sdk/insecure-64', () => ({
  loadCircuits: async () => {
    sdkState.loads.push('insecure-64')
    return { preset: 'insecure-64' }
  },
}))

vi.mock('@crisp-e3/sdk/secure-8192', () => ({
  loadCircuits: async () => {
    sdkState.loads.push('secure-8192')
    return { preset: 'secure-8192' }
  },
}))

import { ensureCircuits } from '../../../client/src/utils/circuits'

afterEach(() => {
  sdkState.current = null
  sdkState.loads = []
})

describe('client ensureCircuits', () => {
  it('reloads a completed preset when switching back to it', async () => {
    await ensureCircuits(0)
    await ensureCircuits(2)
    await ensureCircuits(0)

    expect(sdkState.current).toBe('insecure-64')
    expect(sdkState.loads).toEqual(['insecure-64', 'secure-8192', 'insecure-64'])
  })
})
