// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { beforeEach, describe, expect, it, vi } from 'vitest'

// The SIMD slots of the published output. `decodePlaintextSlots` needs the wasm module of the
// Interfold SDK, so the tests pass the slots in directly.
let outputSlots: bigint[] = []
vi.mock('@interfold/sdk', () => ({ decodePlaintextSlots: async () => outputSlots }))

import { DEGREE, LEVELS, readRegionOutput, slotIndex } from './index'

/** The hex of a plaintext output. The mocked decoder ignores its value. */
const OUTPUT = `0x${'00'.repeat(128 * 8)}`

const zeros = () => new Array<bigint>(DEGREE).fill(0n)

describe('readRegionOutput', () => {
  beforeEach(() => {
    outputSlots = zeros()
  })

  it('reports the non-zero pattern of each region and the highest non-zero level', async () => {
    outputSlots[slotIndex(0, 3)] = 5n
    outputSlots[slotIndex(1, 7)] = 1n
    const output = await readRegionOutput(OUTPUT, 2)
    expect(output.set[0].map(Boolean).indexOf(true)).toBe(3)
    expect(output.set[1][7]).toBe(true)
    expect(output.set).toHaveLength(2)
    expect(output.set[0]).toHaveLength(LEVELS)
    expect(output.topLevel).toBe(7)
    expect(output.unusedGroupsZero).toBe(true)
  })

  it('has no top level when every slot is zero', async () => {
    expect((await readRegionOutput(OUTPUT, 3)).topLevel).toBeNull()
  })

  it('reports a non-zero slot beyond the bidder regions', async () => {
    outputSlots[2 * LEVELS] = 1n
    expect(await readRegionOutput(OUTPUT, 2)).toMatchObject({ unusedGroupsZero: false })
    expect(await readRegionOutput(OUTPUT, 3)).toMatchObject({ unusedGroupsZero: true })
  })

  it('accepts the output with and without the 0x prefix', async () => {
    await expect(readRegionOutput(OUTPUT.slice(2), 2)).resolves.toBeDefined()
  })

  it('refuses a bidder count outside 2 to 8', async () => {
    await expect(readRegionOutput(OUTPUT, 1)).rejects.toThrow()
    await expect(readRegionOutput(OUTPUT, 9)).rejects.toThrow()
    await expect(readRegionOutput(OUTPUT, 2.5)).rejects.toThrow()
  })

  it('refuses an output that is too short', async () => {
    await expect(readRegionOutput('0x00', 2)).rejects.toThrow()
  })
})
