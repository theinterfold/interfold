// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { lcg, randomSale } from '../test-vectors/random-sales'
import {
  type Clearing,
  KIND_CAPPED,
  KIND_UNCAPPED,
  KIND_UNDERSUBSCRIBED,
  claimAmounts,
  clearSale,
  compareStep,
  marginalFills,
} from './clearing'
import { type Grid, coarseProbeMask, searchRound1, searchRound2 } from './probes'
import { demandSums, simulateSale } from './simulate'

interface VectorCase {
  name: string
  input: { prices: string[]; supply: string; budgetUnit: string; saleDecimals: number; sums1: string[]; sums2: string[] }
  expected: {
    round1: { valid: boolean; lo: number; hi: number; probeMask2: number }
    round2: { valid: boolean; lstar: number; sums: string[] } | null
    clearing: { kind: number; step: number; pStar: string; sold: string; remaining: string } | null
    claims: { cmp: 0 | 1 | 2; budgetUnits: number; escrowUnits: number; tokens: string; paid: string; refund: string }[]
  }
}

const vectors = JSON.parse(
  readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '../test-vectors/clearing.json'), 'utf8'),
) as {
  cases: VectorCase[]
}

const big = (values: string[]) => values.map(BigInt)

describe('the vectors of the Solidity libraries', () => {
  it('has the random cases and the invalid one', () => {
    expect(vectors.cases.length).toBeGreaterThan(50)
    expect(vectors.cases.some((c) => c.expected.round2 === null)).toBe(true)
  })

  for (const vector of vectors.cases) {
    it(`${vector.name}: the mirror gives the same search, clearing and payouts`, () => {
      const { input, expected } = vector
      const grid: Grid = {
        prices: big(input.prices.slice(0, input.prices.length)),
        supply: BigInt(input.supply),
        budgetUnit: BigInt(input.budgetUnit),
        saleDecimals: input.saleDecimals,
      }
      const round1 = searchRound1(grid, big(input.sums1))
      expect(round1).toEqual(expected.round1)
      if (!round1.valid) return expect(expected.round2).toBeNull()
      const round2 = searchRound2(grid, big(input.sums1), big(input.sums2), round1.lo, round1.probeMask2)
      expect(round2.valid).toBe(expected.round2?.valid)
      if (!round2.valid) return expect(expected.clearing).toBeNull()
      expect(round2.lstar).toBe(expected.round2?.lstar)
      expect(round2.sums.map(String)).toEqual(expected.round2?.sums)
      const clearing = clearSale(grid, round2.lstar, round2.sums)
      expect({ ...clearing, pStar: String(clearing.pStar), sold: String(clearing.sold), remaining: String(clearing.remaining) }).toEqual(
        expected.clearing,
      )
      for (const claim of expected.claims) {
        const amounts = claimAmounts(grid, clearing, claim)
        expect([amounts.tokens, amounts.paid, amounts.refund].map(String), JSON.stringify(claim)).toEqual([
          claim.tokens,
          claim.paid,
          claim.refund,
        ])
      }
    })
  }
})

/** 8 steps at 1..8 USDC, 100 tokens of 18 decimals, 1 USDC per budget unit. */
const GRID: Grid = {
  prices: [1, 2, 3, 4, 5, 6, 7, 8].map((p) => BigInt(p) * 1_000_000n),
  supply: 100n * 10n ** 18n,
  budgetUnit: 1_000_000n,
  saleDecimals: 18,
}
const sums = (entries: Record<number, number>) => Array.from({ length: 16 }, (_, l) => BigInt(entries[l] ?? 0))

describe('clearSale', () => {
  it('undersubscribed: the demand at the floor price buys less than the supply', () => {
    const c = clearSale(GRID, 0, sums({ 0: 10, 1: 10 }))
    expect(c).toEqual({ kind: KIND_UNDERSUBSCRIBED, step: 0, pStar: 1_000_000n, sold: 10n * 10n ** 18n, remaining: 0n })
  })
  it('uncapped: the price is the demand over the supply, rounded up', () => {
    const c = clearSale(GRID, 1, sums({ 1: 150, 2: 0 }))
    expect(c.kind).toBe(KIND_UNCAPPED)
    expect(c.pStar).toBe(1_500_000n)
    expect(c.sold).toBe(100n * 10n ** 18n)
  })
  it('capped: the bids above the step take their share, the rest of the supply is R', () => {
    const c = clearSale(GRID, 5, sums({ 5: 800, 6: 400 }))
    expect(c.kind).toBe(KIND_CAPPED)
    expect(c.pStar).toBe(6_000_000n)
    expect(c.sold).toBe(GRID.supply)
    expect(c.remaining).toBe(GRID.supply - (400n * 10n ** 18n) / 6n)
  })
  it('capped at the top step: nothing above', () => {
    const c = clearSale(GRID, 7, sums({ 7: 900 }))
    expect(c).toMatchObject({ kind: KIND_CAPPED, step: 7, remaining: GRID.supply })
  })
})

describe('claims', () => {
  const capped: Clearing = clearSale(GRID, 5, sums({ 5: 800, 6: 400 }))
  it('compares the step of a bid with the clearing step', () => {
    expect([compareStep(2, 5), compareStep(5, 5), compareStep(7, 5)]).toEqual([0, 1, 2])
  })
  it('a bid above the step pays the uniform price; one below gets its escrow back', () => {
    const above = claimAmounts(GRID, capped, { cmp: 2, budgetUnits: 400, escrowUnits: 1000 })
    expect(above.tokens).toBe((400n * 10n ** 18n) / 6n)
    expect(above.paid).toBe(400n * 1_000_000n - (400n * 1_000_000n * 10n ** 18n - above.tokens * 6_000_000n) / 10n ** 18n)
    expect(above.paid + above.refund).toBe(1000n * 1_000_000n)
    expect(claimAmounts(GRID, capped, { cmp: 0, budgetUnits: 0, escrowUnits: 10 })).toEqual({ tokens: 0n, paid: 0n, refund: 10_000_000n })
  })
  it('a capped bid at the step gets the refund only: its fill comes from marginalFills', () => {
    expect(claimAmounts(GRID, capped, { cmp: 1, budgetUnits: 100, escrowUnits: 100 })).toEqual({
      tokens: 0n,
      paid: 0n,
      refund: 100_000_000n,
    })
  })
  it('an uncapped bid at the step is paid at once', () => {
    const uncapped = clearSale(GRID, 1, sums({ 1: 150 }))
    expect(claimAmounts(GRID, uncapped, { cmp: 1, budgetUnits: 50, escrowUnits: 100 }).tokens).toBe(
      (50n * 10n ** 18n * 1_000_000n) / 1_500_000n,
    )
  })
})

describe('marginalFills', () => {
  const clearing = clearSale(GRID, 5, sums({ 5: 800, 6: 400 }))
  const claim = (index: number) => ({ index, budgetUnits: 100, escrowUnits: 100 })
  it('fills the claims first bid first, whatever the order they are listed', () => {
    const forward = marginalFills(GRID, clearing, [1, 2, 3, 4].map(claim))
    const full = (100n * 10n ** 18n) / 6n
    expect(forward.map((a) => a.tokens)).toEqual([full, full, clearing.remaining - 2n * full, 0n])
    expect(clearing.remaining - 2n * full).toBe(2n)
    const shuffled = marginalFills(GRID, clearing, [4, 2, 3, 1].map(claim))
    expect(shuffled.map((a) => a.tokens)).toEqual([0n, full, 2n, full])
  })
  it('a claim that did not register leaves its place to the next', () => {
    const fills = marginalFills(GRID, clearing, [3, 4].map(claim))
    expect(fills[0].tokens).toBe((100n * 10n ** 18n) / 6n)
    expect(fills[1].tokens).toBe(fills[0].tokens)
  })
  it('each fill pays the rounded-up price and gets the rest of its escrow back', () => {
    for (const fill of marginalFills(GRID, clearing, [1, 2, 3, 4].map(claim))) {
      expect(fill.paid).toBe((fill.tokens * 6_000_000n + 10n ** 18n - 1n) / 10n ** 18n)
      expect(fill.paid + fill.refund).toBe(100_000_000n)
    }
  })
  it('a smaller remainder cuts the first claims too', () => {
    const tight: Clearing = { ...clearing, remaining: 10n * 10n ** 18n }
    const [a, b] = marginalFills(GRID, tight, [claim(0), claim(1)])
    expect([a.tokens, b.tokens]).toEqual([10n * 10n ** 18n, 0n])
  })
})

describe('simulateSale', () => {
  it('on 300 random sales: the clearing sells at most the supply, the bids at most what was sold', () => {
    for (let seed = 1; seed <= 300; seed++) {
      const { grid, bids } = randomSale(lcg(seed * 7919))
      const sim = simulateSale(grid, bids)
      expect(sim.clearing, `seed ${seed}`).not.toBeNull()
      const clearing = sim.clearing!
      expect(clearing.sold <= grid.supply, `seed ${seed}`).toBe(true)
      expect(sim.outcomes.reduce((sum, o) => sum + o.tokens, 0n) <= clearing.sold, `seed ${seed}`).toBe(true)
      sim.outcomes.forEach((o, i) => {
        expect(o.paid + o.refund).toBe(BigInt(bids[i].escrow) * grid.budgetUnit)
        expect(o.refund >= 0n && o.paid >= 0n).toBe(true)
      })
      // The probe search found the step of the full demand curve.
      const full = demandSums(bids)
      expect(sim.full).toEqual(full)
      expect(coarseProbeMask(grid.prices.length) & sim.round1.probeMask2).toBe(0)
    }
  })
})
