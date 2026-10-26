// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import {
  BUDGET_BITS,
  budgetDigits,
  bidSlots,
  CLAIM_TREE_DEPTH,
  coefficientsToPlaintext,
  coefficientsToSlots,
  CONFIG_DOMAIN,
  configBytes,
  countedBitmap,
  decodeOutput,
  decodePlaintext,
  DIGIT_BITS,
  FLAG_BASE,
  FLAG_CELLS,
  FLAGS_PER_CELL,
  INPUT_TREE_DEPTH,
  keepMask,
  LANES,
  levelSum,
  LEVELS_MAX,
  MAX_BIDDERS,
  MAX_TIERS,
  PLAINTEXT_MODULUS,
  plaintextToCoefficients,
  SLOTS,
  slotsToCoefficients,
} from './layout'

const vectorsDir = join(dirname(fileURLToPath(import.meta.url)), '../test-vectors')
const readVectors = <T>(name: string): T => JSON.parse(readFileSync(join(vectorsDir, name), 'utf8')) as T

interface LayoutVectors {
  constants: Record<string, number>
  config: { domain: string; role: 1 | 2; levels: number; probeMask: number; bytes: string }
  bidSlots: { step: number; budget: number; index: number; slots: number[] }[]
  keepMasks: { probeMask: number; slots: number[] }[]
  outputs: {
    name: string
    probeMask: number
    bids: { step: number; budget: number; index: number }[]
    slots: number[]
    plaintext: string
    cells: number[][]
    flagCells: number[]
    levelSums: number[]
    countedBitmap: string
  }[]
}

const layout = readVectors<LayoutVectors>('layout.json')

describe('constants', () => {
  it('match the Rust layout', () => {
    expect(layout.constants).toEqual({
      LEVELS_MAX,
      DIGIT_BITS,
      LANES,
      BUDGET_BITS,
      MAX_BIDDERS,
      FLAGS_PER_CELL,
      FLAG_BASE,
      FLAG_CELLS,
      SLOTS,
      CLAIM_TREE_DEPTH,
      MAX_TIERS,
      INPUT_TREE_DEPTH,
      PLAINTEXT_MODULUS,
    })
  })
})

describe('bid slots', () => {
  it.each(layout.bidSlots.map((v) => [`${v.step}/${v.budget}/${v.index}`, v] as const))('%s matches the Rust layout', (_name, v) => {
    expect(Array.from(bidSlots(v))).toEqual(v.slots.map(BigInt))
  })

  it('splits a budget into little endian base 4 digits', () => {
    expect(budgetDigits(1234)).toEqual([2, 0, 1, 3, 0, 1])
    expect(budgetDigits(1)).toEqual([1, 0, 0, 0, 0, 0])
    expect(budgetDigits(4095)).toEqual([3, 3, 3, 3, 3, 3])
  })

  it('rejects what the bid circuit rejects', () => {
    expect(() => bidSlots({ step: LEVELS_MAX, budget: 1, index: 0 })).toThrow()
    expect(() => bidSlots({ step: 0, budget: 0, index: 0 })).toThrow()
    expect(() => bidSlots({ step: 0, budget: 4096, index: 0 })).toThrow()
    expect(() => bidSlots({ step: 0, budget: 1, index: MAX_BIDDERS })).toThrow()
    expect(() => bidSlots({ step: 0.5, budget: 1, index: 0 })).toThrow()
  })
})

describe('keep mask', () => {
  it.each(layout.keepMasks.map((v) => [`0x${v.probeMask.toString(16)}`, v] as const))('%s matches the Rust layout', (_name, v) => {
    expect(Array.from(keepMask(v.probeMask))).toEqual(v.slots.map(BigInt))
  })

  it('rejects a mask that is not a u16', () => {
    expect(() => keepMask(0x10000)).toThrow()
    expect(() => keepMask(-1)).toThrow()
  })
})

describe('config', () => {
  it('encodes like the Rust program', () => {
    const { domain, role, levels, probeMask, bytes } = layout.config
    expect(CONFIG_DOMAIN).toBe(domain)
    expect(configBytes(role, levels, probeMask)).toBe(bytes)
  })

  it('rejects a role, levels or mask the program would not parse', () => {
    expect(() => configBytes(3 as 1, 12, 0)).toThrow()
    expect(() => configBytes(1, 7, 0)).toThrow()
    expect(() => configBytes(1, 17, 0)).toThrow()
    expect(() => configBytes(1, 12, 0x10000)).toThrow()
  })
})

describe('output', () => {
  it.each(layout.outputs.map((v) => [v.name, v] as const))('%s decodes like the Rust layout', (_name, v) => {
    const output = decodeOutput(v.slots, v.bids.length === 0 ? 0 : Math.max(...v.bids.map((b) => b.index)) + 1)
    expect(output.cells).toEqual(v.cells)
    expect(output.flagCells).toEqual(v.flagCells)
    expect(Array.from({ length: LEVELS_MAX }, (_, l) => levelSum(output.cells, l))).toEqual(v.levelSums.map(BigInt))
    expect(countedBitmap(output.flagCells)).toBe(BigInt(v.countedBitmap))
    expect(decodePlaintext(v.plaintext)).toEqual(decodeOutput(v.slots))
  })

  it.each(layout.outputs.map((v) => [v.name, v] as const))('%s: the SIMD conversion matches the fhe.rs plaintext', (_name, v) => {
    expect(coefficientsToSlots(plaintextToCoefficients(v.plaintext))).toEqual(v.slots)
    expect(coefficientsToPlaintext(slotsToCoefficients(v.slots))).toBe(v.plaintext)
  })

  it('sums the bids of the vectors the way the chain does', () => {
    for (const v of layout.outputs) {
      const sum = new Array<number>(SLOTS).fill(0)
      for (const bid of v.bids) {
        bidSlots(bid).forEach((slot, i) => {
          sum[i] = (sum[i] + Number(slot)) % PLAINTEXT_MODULUS
        })
      }
      const mask = keepMask(v.probeMask)
      expect(sum.map((slot, i) => slot * Number(mask[i]))).toEqual(v.slots)
    }
  })

  it('rejects an output that no sale can produce', () => {
    const slots = new Array<number>(SLOTS).fill(0)
    expect(() => decodeOutput(slots.slice(1))).toThrow('slots')
    expect(() => decodeOutput(slots.map((_, i) => (i === 0 ? PLAINTEXT_MODULUS : 0)))).toThrow('not below')
    // A cell above 3 * bidCount.
    expect(() =>
      decodeOutput(
        slots.map((_, i) => (i === 0 ? 7 : 0)),
        2,
      ),
    ).toThrow('cell')
    expect(
      decodeOutput(
        slots.map((_, i) => (i === 0 ? 6 : 0)),
        2,
      ).cells[0][0],
    ).toBe(6)
    // A counted flag at or above the bid count.
    expect(() =>
      decodeOutput(
        slots.map((_, i) => (i === FLAG_BASE ? 0b100 : 0)),
        2,
      ),
    ).toThrow('flag')
    expect(
      decodeOutput(
        slots.map((_, i) => (i === FLAG_BASE ? 0b11 : 0)),
        2,
      ).flagCells[0],
    ).toBe(3)
  })
})

describe('level sums and the counted bitmap', () => {
  it('weights the digit j by 4^j', () => {
    expect(levelSum([[2, 0, 1, 3, 0, 1]], 0)).toBe(1234n)
    expect(levelSum([[255, 255, 255, 255, 255, 255]], 0)).toBe(255n * 1365n)
  })

  it('reads the flag bits of cell c as the bids 8c..8c+7', () => {
    const flags = new Array<number>(FLAG_CELLS).fill(0)
    flags[0] = 0b1
    flags[1] = 0b10
    flags[10] = 0b1_0000
    expect(countedBitmap(flags)).toBe(1n | (1n << 9n) | (1n << 84n))
    expect(() => countedBitmap(flags.slice(1))).toThrow()
    expect(() => countedBitmap(flags.map(() => 256))).toThrow()
  })
})

describe('SIMD slots against the fhe.rs decoder', () => {
  const { cases } = readVectors<{ cases: { name: string; plaintext: string; slots: (string | number)[] }[] }>('slots.json')

  it('has cases', () => {
    expect(cases.length).toBeGreaterThan(0)
  })

  it.each(cases.map((vector) => [vector.name, vector] as const))('%s', (_name, vector) => {
    const slots = vector.slots.map(Number)
    const coefficients = plaintextToCoefficients(vector.plaintext)
    expect(coefficientsToSlots(coefficients)).toEqual(slots)
    expect(slotsToCoefficients(slots)).toEqual(coefficients)
    expect(coefficientsToPlaintext(coefficients)).toBe(vector.plaintext)
  })
})
