// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { describe, expect, it } from 'vitest'
import { lcg, randomSale } from '../test-vectors/random-sales'
import { type Grid, coarseProbeMask, overDemand, searchRound1, searchRound2 } from './probes'
import { demandSums, revealed, simulateSale } from './simulate'

const bits = (mask: number): number[] => Array.from({ length: 16 }, (_, l) => l).filter((l) => (mask >> l) & 1)

/** 16 prices 1000, 2000, ..., 16000 for a supply of 10 tokens: `over(m)` is `F[m] > 10000 * m`. */
const GRID: Grid = { prices: Array.from({ length: 16 }, (_, l) => BigInt(l + 1) * 1000n), supply: 10n, budgetUnit: 1n, saleDecimals: 0 }
const sums = (entries: Record<number, number>): bigint[] => Array.from({ length: 16 }, (_, l) => BigInt(entries[l] ?? 0))

describe('coarseProbeMask', () => {
  it('picks the multiples of ceil(levels / 4)', () => {
    expect(bits(coarseProbeMask(16))).toEqual([4, 8, 12])
    expect(bits(coarseProbeMask(8))).toEqual([2, 4, 6])
    expect(bits(coarseProbeMask(9))).toEqual([3, 6])
    expect(bits(coarseProbeMask(10))).toEqual([3, 6, 9])
    expect(bits(coarseProbeMask(13))).toEqual([4, 8, 12])
  })
})

describe('searchRound1', () => {
  it('no over-demand at a probe: lo = 0, and level 0 joins round 2', () => {
    const r = searchRound1(GRID, sums({ 4: 39_000, 8: 30_000, 12: 5_000 }))
    expect(r).toEqual({ valid: true, lo: 0, hi: 4, probeMask2: 0b1111 })
  })
  it('over-demand up to a middle probe', () => {
    // over(4): 50000 > 40000; over(8): 50000 > 80000 is false; over(12) is false: lo = 4, hi = 8.
    const r = searchRound1(GRID, sums({ 4: 50_000, 8: 50_000, 12: 100 }))
    expect(r).toEqual({ valid: true, lo: 4, hi: 8, probeMask2: 0b1110_0000 })
  })
  it('over-demand at the top probe: hi = levels', () => {
    const r = searchRound1(GRID, sums({ 4: 200_000, 8: 150_000, 12: 130_000 }))
    expect(r).toEqual({ valid: true, lo: 12, hi: 16, probeMask2: 0b1110_0000_0000_0000 })
  })
  it('rejects sums that increase with the level', () => {
    expect(searchRound1(GRID, sums({ 4: 10, 8: 11, 12: 0 })).valid).toBe(false)
    expect(searchRound1(GRID, sums({ 4: 10, 8: 5, 12: 6 })).valid).toBe(false)
  })
  it('a bracket with nothing in it needs no round 2 levels', () => {
    // L = 10: probes 3, 6, 9; lo = 9 leaves hi = 10 and nothing between.
    const grid: Grid = { ...GRID, prices: GRID.prices.slice(0, 10) }
    const r = searchRound1(grid, sums({ 3: 400_000, 6: 300_000, 9: 200_000 }))
    expect(r).toEqual({ valid: true, lo: 9, hi: 10, probeMask2: 0 })
  })
})

describe('searchRound2', () => {
  const sums1 = sums({ 4: 80_000, 8: 50_000, 12: 100 })
  const round1 = searchRound1(GRID, sums1)
  // lo = 4, hi = 8, P2 = {5, 6, 7}: over(5) = F > 50000, over(6) = F > 60000, over(7) = F > 70000.
  const mask2 = round1.probeMask2
  it('the step stays at lo when no level of the bracket has over-demand', () => {
    expect(round1).toMatchObject({ lo: 4, hi: 8 })
    const r = searchRound2(GRID, sums1, sums({ 5: 50_000, 6: 50_000, 7: 50_000 }), round1.lo, mask2)
    expect(r.valid).toBe(true)
    expect(r.lstar).toBe(4)
    expect(r.sums).toEqual(sums({ 4: 80_000, 5: 50_000, 6: 50_000, 7: 50_000, 8: 50_000, 12: 100 }))
  })
  it('the step moves up inside the bracket', () => {
    const r = searchRound2(GRID, sums1, sums({ 5: 75_000, 6: 65_000, 7: 60_000 }), round1.lo, mask2)
    expect(r).toMatchObject({ valid: true, lstar: 6 })
  })
  it('the step reaches the last level of the bracket', () => {
    const r = searchRound2(GRID, sums1, sums({ 5: 79_000, 6: 78_000, 7: 71_000 }), round1.lo, mask2)
    expect(r).toMatchObject({ valid: true, lstar: 7 })
  })
  it('rejects a merged curve that increases', () => {
    expect(searchRound2(GRID, sums1, sums({ 5: 80_001, 6: 0, 7: 0 }), round1.lo, mask2).valid).toBe(false)
    expect(searchRound2(GRID, sums1, sums({ 5: 70_000, 6: 60_000, 7: 60_001 }), round1.lo, mask2).valid).toBe(false)
    // F7 below F8 breaks the order against round 1.
    expect(searchRound2(GRID, sums1, sums({ 5: 70_000, 6: 60_000, 7: 49_999 }), round1.lo, mask2).valid).toBe(false)
  })
  it('with lo = 0 level 0 is revealed, and the step can stay 0', () => {
    const small = sums({ 4: 5_000, 8: 1_000, 12: 0 })
    const r1 = searchRound1(GRID, small)
    expect(r1).toEqual({ valid: true, lo: 0, hi: 4, probeMask2: 0b1111 })
    const r = searchRound2(GRID, small, sums({ 0: 90_000, 1: 9_000, 2: 8_000, 3: 7_000 }), 0, r1.probeMask2)
    expect(r).toMatchObject({ valid: true, lstar: 0 })
    expect(r.sums[0]).toBe(90_000n)
  })
})

describe('over-demand', () => {
  it('is strict', () => {
    expect(overDemand(GRID, 1, 10_000n)).toBe(false)
    expect(overDemand(GRID, 1, 10_001n)).toBe(true)
  })
})

describe('the probe search finds the step of the full curve', () => {
  it('on 400 random sales, with at most 7 revealed sums', () => {
    const seen = { zero: 0, top: 0, middle: 0 }
    for (let seed = 1; seed <= 400; seed++) {
      const { grid, bids } = randomSale(lcg(seed * 104729))
      const full = demandSums(bids)
      const levels = grid.prices.length
      // The step of the full curve: the highest level with over-demand.
      let truth = 0
      for (let m = 1; m < levels; m++) if (overDemand(grid, m, full[m])) truth = m
      const sim = simulateSale(grid, bids)
      expect(sim.round1.valid, `seed ${seed}`).toBe(true)
      expect(sim.round2?.valid, `seed ${seed}`).toBe(true)
      expect(sim.round2?.lstar, `seed ${seed}`).toBe(truth)
      const known = coarseProbeMask(levels) | sim.round1.probeMask2
      expect(bits(known).length, `seed ${seed}`).toBeLessThanOrEqual(7)
      const mask1 = coarseProbeMask(levels)
      expect(sim.round2?.sums).toEqual(revealed(full, known))
      expect(bits(mask1).length).toBeLessThanOrEqual(3)
      if (truth === 0) seen.zero++
      else if (truth >= levels - 1 - Math.ceil(levels / 4)) seen.top++
      else seen.middle++
    }
    expect(seen.zero).toBeGreaterThan(5)
    expect(seen.top).toBeGreaterThan(5)
    expect(seen.middle).toBeGreaterThan(5)
  })
})
