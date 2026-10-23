// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * The operation counts and the depth must equal what the Rust crate reports. The numbers below
 * come from `auction-designs --sweep 2,3,4,5,8 --levels 8` on the toy profile (ct×ct, ct×pt,
 * depth). The TS depth is measured on the output, and the Rust depth is the formula of the
 * design: the two must agree.
 */

import { describe, expect, it } from 'vitest'
import { designs, run, seededRng, SetupError } from '../src'

type Counts = [ciphertextProducts: number, plaintextProducts: number, depth: number]

/** design -> bidders -> [ct×ct, ct×pt, depth] as printed by the Rust binary. */
const RUST: Record<string, Record<number, Counts | null>> = {
  rank: { 2: [4, 4, 2], 3: [6, 7, 2], 4: [8, 10, 2], 5: [10, 13, 2], 8: [16, 22, 2] },
  'rank-batched': { 2: [2, 1, 2], 3: [2, 1, 2], 4: [2, 1, 2], 5: [2, 1, 2], 8: null },
  'first-price': { 2: [1, 0, 1], 3: [2, 0, 2], 4: [3, 0, 2], 5: [4, 0, 3], 8: [7, 0, 3] },
  'first-price-blind': { 2: [1, 0, 1], 3: [1, 0, 1], 4: [1, 0, 1], 5: [1, 0, 1], 8: [1, 0, 1] },
  'second-price': { 2: [5, 2, 2], 3: [10, 3, 3], 4: [15, 4, 3], 5: [20, 5, 4], 8: [35, 8, 4] },
  'second-price-blind': { 2: [2, 0, 2], 3: [2, 0, 2], 4: [2, 0, 2], 5: [2, 0, 2], 8: [2, 0, 2] },
  vickrey: { 2: [4, 6, 3], 3: [4, 9, 3], 4: [4, 12, 3], 5: [4, 15, 3], 8: [4, 24, 3] },
  'vickrey-compact': { 2: [6, 8, 4], 3: [7, 12, 4], 4: [8, 16, 4], 5: [9, 20, 4], 8: [12, 32, 4] },
  'rl-first-price': { 2: [1, 2, 1], 3: [1, 3, 1], 4: [1, 4, 1], 5: [1, 5, 1], 8: [1, 8, 1] },
  'rl-second-price': { 2: [6, 4, 3], 3: [6, 6, 3], 4: [6, 8, 3], 5: [6, 10, 3], 8: [6, 16, 3] },
}

describe('operation counts and depth equal the Rust crate', () => {
  for (const [name, byBidders] of Object.entries(RUST)) {
    for (const [bidders, expected] of Object.entries(byBidders)) {
      const n = Number(bidders)
      // The counts do not depend on the bids: try the lowest and the highest bids.
      const bidSets = [new Array<number>(n).fill(0), Array.from({ length: n }, (_, i) => (i * 3) % 8)]
      it(`${name}, ${n} bidders`, () => {
        if (expected === null) {
          // 3 · n² · B = 3 · 64 · 8 coefficients do not fit the 1024 toy slots.
          expect(() => run(name, 'toy', bidSets[0], 8)).toThrow(SetupError)
          return
        }
        for (const bids of bidSets) {
          const result = run(name, 'toy', bids, 8, undefined, seededRng(n))
          expect([result.opCounts.ciphertextProducts, result.opCounts.plaintextProducts, result.depth]).toEqual(expected)
          expect(designs[name].depth(n)).toBe(expected[2])
        }
      })
    }
  }

  it('n = 4 at 16 levels, as in the Rust summary table', () => {
    const rust: Record<string, Counts> = {
      rank: [8, 10, 2],
      'rank-batched': [2, 1, 2],
      'first-price': [3, 0, 2],
      'first-price-blind': [1, 0, 1],
      'second-price': [15, 4, 3],
      'second-price-blind': [2, 0, 2],
      vickrey: [4, 12, 3],
      'vickrey-compact': [8, 16, 4],
      'rl-first-price': [1, 4, 1],
      'rl-second-price': [6, 8, 3],
    }
    for (const [name, expected] of Object.entries(rust)) {
      const result = run(name, 'toy', [9, 3, 9, 9], 16, undefined, seededRng(1))
      expect([result.opCounts.ciphertextProducts, result.opCounts.plaintextProducts, result.depth], name).toEqual(expected)
    }
  })
})
