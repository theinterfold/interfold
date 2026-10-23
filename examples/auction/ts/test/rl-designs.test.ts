// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * The ratio-lane designs. The tie set and the price come from plain loops over the bids here, and
 * the winner from the sum of the plaintext masks, so none of the program code decides the
 * expected value.
 */

import { describe, expect, it } from 'vitest'
import {
  inverse,
  isCorrect,
  rlFirstPrice,
  rlSecondPrice,
  rlSecondPriceCopies,
  run,
  seededRng,
  SetupError,
  type AnyDesign,
  type LaneReadout,
  type RunResult,
} from '../src'

const LEVELS = 16
const designsUnderTest = [rlFirstPrice, rlSecondPrice]

/** The bidders with the highest bid. */
function topBidders(bids: number[]): number[] {
  const top = Math.max(...bids)
  return bids.flatMap((bid, i) => (bid === top ? [i] : []))
}

/** The price level of each rule: the highest bid, or the second-highest bid. */
function priceOf(design: AnyDesign, bids: number[]): number {
  const sorted = [...bids].sort((a, b) => b - a)
  return design.priceRule === 'first' ? sorted[0] : sorted[1]
}

/** `n` bids with a tie for the highest bid at the bidders `tied`, and other bids below it. */
function bidsWithTie(n: number, tied: number[], top: number): number[] {
  return Array.from({ length: n }, (_, i) => (tied.includes(i) ? top : i % top))
}

function lane(report: RunResult): LaneReadout {
  return report.design.readLanes!(report.setup, report.outputSlots)
}

describe.each(designsUnderTest)('$name', (design) => {
  it('names the price, the tie set, and a winner from the tie set, on bids with and without ties', () => {
    const rng = seededRng(21)
    const bidSets = [
      [7, 3, 9, 9],
      [9, 9, 3, 7],
      [5, 5, 5, 5, 5],
      [0, 15],
      [15, 0],
      [0, 0],
      [1, 14, 2, 13, 3, 12, 4, 11],
    ]
    for (const bids of bidSets) {
      const report = run(design, 'toy', bids, LEVELS, undefined, rng)
      expect(isCorrect(report), `${design.name} on ${bids}`).toBe(true)
      expect(report.result.price, `${design.name} on ${bids}`).toBe(priceOf(design, bids))
      expect(report.result.tieSet).toEqual(topBidders(bids))
      expect(report.result.tieSet).toContain(report.result.winner)
    }
  })

  // Weight groups hold 13 bidders on the toy profile (t = 12289) and 16 on the demo profile
  // (t = 65537). The tie set must cross the group borders.
  it('reads a tie set across weight groups', () => {
    const cases: ['toy' | 'demo', number, number[]][] = [
      ['toy', 14, [12, 13]],
      ['toy', 30, [0, 12, 13, 26, 29]],
      ['toy', 28, [25, 27]],
      ['demo', 20, [3, 15, 16, 17]],
    ]
    for (const [profile, n, tied] of cases) {
      const bids = bidsWithTie(n, tied, 6)
      const report = run(design, profile, bids, 8, undefined, seededRng(n))
      expect(report.result.tieSet, `${profile}, ${n} bidders`).toEqual(tied)
      expect(isCorrect(report), `${profile}, ${n} bidders`).toBe(true)
    }
  })

  it('draws the winner of a tie from the whole tie set, and never outside it', () => {
    const bids = [5, 5, 2, 5]
    const wins = [0, 0, 0, 0]
    for (let seed = 0; seed < 90; seed++) {
      const report = run(design, 'toy', bids, LEVELS, undefined, seededRng(seed))
      expect(isCorrect(report)).toBe(true)
      wins[report.result.winner as number]++
    }
    expect(wins[2]).toBe(0)
    // 90 draws over 3 bidders: each wins about 30 times.
    for (const bidder of [0, 1, 3]) expect(wins[bidder], `wins ${wins}`).toBeGreaterThan(10)
  })

  it('gives the winner to the only top bidder, whatever the random lane', () => {
    for (let seed = 0; seed < 20; seed++) {
      const report = run(design, 'toy', [3, 12, 9, 2], LEVELS, undefined, seededRng(seed))
      expect(report.result.winner).toBe(1)
      expect(report.result.tieSet).toEqual([1])
    }
  })

  // The lanes above the price are 0, the lanes at it carry the result, and the lanes below it are
  // uniform: no zeros, and a different value for another mask.
  it('is 0 above the price level, and uniform non-zero below it', () => {
    const bids = [3, 12, 9, 2]
    const price = priceOf(design, bids)
    const rows = lane(run(design, 'toy', bids, LEVELS, undefined, seededRng(2))).rows
    for (const row of rows) {
      expect(row.kinds.slice(price + 1), row.name).toEqual(new Array(LEVELS - price - 1).fill('zero'))
      expect(row.kinds.slice(0, price), row.name).toEqual(new Array(price).fill('random'))
    }
    const other = lane(run(design, 'toy', bids, LEVELS, undefined, seededRng(3))).rows
    const same = rows.flatMap((row, i) => row.values.slice(0, price).filter((value, p) => value === other[i].values[p]))
    expect(same.length).toBeLessThanOrEqual(1)
  })

  // Two bid sets with the same price, the same tie set, and the same masks give the same output
  // at and above the price level. The bids below do not show.
  it('shows only the price, the tie set, and the random lane', () => {
    // The first price of both sets is 9 (tie set 1 and 3). The second price is 9 too.
    const sets = [
      [2, 9, 4, 9],
      [8, 9, 0, 9],
      [0, 9, 8, 9],
    ]
    const reports = sets.map((bids) => run(design, 'toy', bids, LEVELS, undefined, seededRng(5)))
    const readouts = reports.map(lane)
    for (const readout of readouts) {
      expect(readout.price).toBe(9)
      expect(readout.tieSet).toEqual([1, 3])
      expect(readout.groupValues).toEqual(readouts[0].groupValues)
      expect(readout.random).toBe(readouts[0].random)
      expect(readout.rows.map((row) => row.kinds)).toEqual(readouts[0].rows.map((row) => row.kinds))
    }
  })
})

describe('rl-first-price', () => {
  it('reads an output that names a bidder outside its group as no result', () => {
    const report = run(rlFirstPrice, 'toy', [4, 9, 2], LEVELS, undefined, seededRng(1))
    const slots = [...report.outputSlots]
    // 3 bidders: group 0 has 3 bits. The value 8 has bit 3.
    slots[9] = 8
    const readout = rlFirstPrice.readLanes!(report.setup, slots)
    expect(readout.winner).toBeNull()
    expect(readout.tieSet).toEqual([])
    // An output with every lane at 0 also names nothing.
    expect(rlFirstPrice.readLanes!(report.setup, new Array(slots.length).fill(0)).price).toBeNull()
  })
})

/** `design` with the pair mask of every bidder changed by `change`. */
function tamperedPairMask(change: (mask: number[], setup: RunResult['setup']) => void): AnyDesign {
  return {
    ...rlSecondPrice,
    encodeBid(setup, index, bid, rng) {
      const encoded = rlSecondPrice.encodeBid(setup, index, bid, rng)
      change(encoded.plaintexts[3], setup)
      return encoded
    },
  }
}

describe('rl-second-price copies and the pair mask', () => {
  // The price is read in each copy, and the highest wins. A copy with R = 0 at the price reads
  // too low; the other copies fix the price.
  it('reads the price from a copy whose pair mask is non-zero at the price', () => {
    const bids = [3, 12, 9, 2]
    const levels = LEVELS
    // One copy is 2 blocks of 16 slots. Zero the pair mask at level 9 in every copy except the last.
    const keepLast = tamperedPairMask((mask, setup) => {
      for (let copy = 0; copy < rlSecondPriceCopies(setup) - 1; copy++) {
        for (const block of [0, 1]) mask[(copy * 2 + block) * levels + 9] = 0
      }
    })
    const report = run(keepLast, 'toy', bids, levels, undefined, seededRng(4))
    expect(report.result).toMatchObject({ winner: 1, price: 9 })
    const everyCopy = tamperedPairMask((mask, setup) => {
      for (let copy = 0; copy < rlSecondPriceCopies(setup); copy++) {
        for (const block of [0, 1]) mask[(copy * 2 + block) * levels + 9] = 0
      }
    })
    // With R = 0 at the price in every copy, the price reads too low: the documented t^-copies error.
    expect(run(everyCopy, 'toy', bids, levels, undefined, seededRng(4)).result.price).toBeLessThan(9)
  })

  // Without the shape proof a bidder could make R differ in the y lane and in the z lane. The
  // ratio then is not L, and the decoded tie set changes: this is why the shape is proven.
  it('needs the pair mask to be equal in the y lane and the z lane', () => {
    const bids = [3, 12, 9, 2]
    const broken = tamperedPairMask((mask, setup) => {
      for (let copy = 0; copy < rlSecondPriceCopies(setup); copy++) {
        for (let level = 0; level < LEVELS; level++)
          mask[(copy * 2 + 1) * LEVELS + level] = (mask[(copy * 2 + 1) * LEVELS + level] + 1) % setup.ring.t
      }
    })
    expect(isCorrect(run(rlSecondPrice, 'toy', bids, LEVELS, undefined, seededRng(4)))).toBe(true)
    expect(isCorrect(run(broken, 'toy', bids, LEVELS, undefined, seededRng(4)))).toBe(false)
  })

  it('shows a ratio of the winner weights at the price and a different ratio below it', () => {
    const bids = [3, 12, 9, 2]
    let atPriceEqual = 0
    let belowEqual = 0
    for (let seed = 0; seed < 30; seed++) {
      const report = run(rlSecondPrice, 'toy', bids, LEVELS, undefined, seededRng(seed))
      const { y, z } = { y: report.outputSlots.slice(0, LEVELS), z: report.outputSlots.slice(LEVELS, 2 * LEVELS) }
      const t = report.setup.ring.t
      const ratioAt = (level: number) => (z[level] * inverse(y[level], t)) % t
      // The winner is bidder 1: weight 2^1.
      if (ratioAt(9) === 2) atPriceEqual++
      if (ratioAt(4) === 2) belowEqual++
    }
    expect(atPriceEqual).toBe(30)
    expect(belowEqual).toBeLessThanOrEqual(1)
  })
})

describe('capacity', () => {
  const kind = (f: () => unknown): string => {
    try {
      f()
    } catch (error) {
      if (error instanceof SetupError) return error.kind
      throw error
    }
    return 'no error'
  }

  it('rl-second-price needs n (n - 1) < t, and rl-first-price needs only n < t', () => {
    // t = 12289: 111 · 110 = 12210 fits, 112 · 111 = 12432 does not.
    const fits = (n: number) => Array.from({ length: n }, (_, i) => i % 4)
    expect(isCorrect(run(rlSecondPrice, 'toy', fits(111), 4, undefined, seededRng(1)))).toBe(true)
    expect(kind(() => run(rlSecondPrice, 'toy', fits(112), 4))).toBe('plaintext-modulus-too-small')
    expect(isCorrect(run(rlFirstPrice, 'toy', fits(112), 4, undefined, seededRng(1)))).toBe(true)
  })

  it('runs 1 level below the slot limit and refuses 1 level above it', () => {
    // Toy ring, N = 1024 slots, 2 bidders: first price keeps B + 1 slots, second price 2B + 1.
    for (const [design, levels] of [
      [rlFirstPrice, 1023],
      [rlSecondPrice, 511],
    ] as [AnyDesign, number][]) {
      expect(isCorrect(run(design, 'toy', [levels - 1, levels - 1], levels, undefined, seededRng(3))), design.name).toBe(true)
      expect(
        kind(() => run(design, 'toy', [0, 0], levels + 1)),
        design.name,
      ).toBe('not-enough-slots')
    }
  })
})
