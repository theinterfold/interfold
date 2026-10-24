// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { existsSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { bidderOutcome, clearing, compareBid, outcomeFromComparison, type Clearing, type ClearingParams } from './clearing'
import { LEVELS } from './layout'

/** A small seeded generator, so a failure is reproducible. */
function lcg(seed: number): () => number {
  let state = seed >>> 0
  return () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0
    return state / 2 ** 32
  }
}

/** The curve `c_l` of the bids `bids`: the number with `b >= l`. */
function curve(bids: readonly number[]): bigint[] {
  return Array.from({ length: LEVELS }, (_, l) => BigInt(bids.filter((b) => b >= l).length))
}

interface Random {
  params: ClearingParams
  bids: number[]
}

function random(next: () => number): Random {
  const levels = 2 + Math.floor(next() * (LEVELS - 1))
  const decimals = [0, 6, 18][Math.floor(next() * 3)]
  const unit = 10n ** BigInt(decimals)
  // Strictly increasing prices with uneven steps.
  const prices: bigint[] = []
  let price = BigInt(1 + Math.floor(next() * 1000))
  for (let l = 0; l < levels; l++) {
    prices.push(price)
    price += BigInt(1 + Math.floor(next() * 500))
  }
  const escrow = BigInt(1 + Math.floor(next() * 10_000)) * (decimals === 0 ? 1n : unit / 1000n + 1n)
  const bidders = 1 + Math.floor(next() * 40)
  const bids = Array.from({ length: bidders }, () => Math.floor(next() * levels))
  // The supply so that some sales clear and some are undersubscribed.
  const natural = (BigInt(bidders) * escrow * unit) / prices[Math.floor(next() * levels)]
  const supply = natural === 0n ? 1n : (natural * BigInt(1 + Math.floor(next() * 300))) / 100n + 1n
  return { params: { prices, supply, escrow, saleDecimals: decimals }, bids }
}

function allocations(result: Clearing, bids: readonly number[]) {
  return bids.map((b) => bidderOutcome(result, b))
}

describe('clearing', () => {
  it('is capped when the bidders above the step fill the supply exactly', () => {
    // p = [10, 20, 30], U = 1, E = 60: a bidder at 10 buys 6, at 20 buys 3, at 30 buys 2.
    const params = { prices: [10n, 20n, 30n], supply: 6n, escrow: 60n, saleDecimals: 0 }
    const result = clearing(params, curve([1, 1, 2, 2, 0]))
    expect(result.kind).toBe('capped')
    // c_2 = 2 demands 4 <= 6 at 30, so the step 2 is not over-demanded; c_1 = 4 demands 12 > 6 at 20.
    expect([result.step, result.pStar]).toEqual([1, 20n])
    expect(result.full).toMatchObject({ tokens: 3n, paid: 60n, refund: 0n })
    // Two full winners take 6 of 6: nothing is left for the two marginal bidders.
    expect(result.marginal).toMatchObject({ tokens: 0n, paid: 0n, refund: 60n })
    expect(result.sold).toBe(6n)
    expect(bidderOutcome(result, 0).status).toBe('loser')
    expect(bidderOutcome(result, 1).status).toBe('marginal')
    expect(bidderOutcome(result, 2).status).toBe('full')
  })

  it('shares the rest among the marginal bidders', () => {
    // p = [10, 20], U = 1, E = 40, S = 10. c_1 = 1, c_0 = 4. At 20 a bidder buys 2.
    const params = { prices: [10n, 20n], supply: 10n, escrow: 40n, saleDecimals: 0 }
    const result = clearing(params, curve([1, 0, 0, 0]))
    // c_1 * E * U = 40 > p_0 * S = 100? no. So not over-demanded at step 1. c_0 = 4: 160 >= 100: capped at 0.
    expect(result.kind).toBe('capped')
    expect(result.step).toBe(0)
    expect(result.pStar).toBe(10n)
    // Full: 4 tokens at 10. Above: one bidder takes 4, the remaining 6 go to 3 marginal bidders: 2 each.
    expect(result.full.tokens).toBe(4n)
    expect(result.marginal).toMatchObject({ tokens: 2n, paid: 20n, refund: 20n })
    expect(result.sold).toBe(10n)
  })

  it('is uncapped between two steps and rounds the price up', () => {
    // p = [10, 20], U = 1, E = 30, S = 4. c_1 = 2: 60 > 40 and 60 < 80: uncapped at 1, pStar = ceil(60 / 4) = 15.
    const params = { prices: [10n, 20n], supply: 4n, escrow: 30n, saleDecimals: 0 }
    const result = clearing(params, curve([1, 1, 0]))
    expect(result.kind).toBe('uncapped')
    expect([result.step, result.k, result.pStar]).toEqual([1, 1, 15n])
    expect(result.full).toMatchObject({ tokens: 2n, paid: 30n, refund: 0n })
    expect(result.sold).toBe(4n)
    expect(bidderOutcome(result, 0).status).toBe('loser')
    expect(bidderOutcome(result, 1).status).toBe('full')
  })

  it('is undersubscribed when demand at the lowest price is below the supply', () => {
    const params = { prices: [10n, 20n], supply: 100n, escrow: 40n, saleDecimals: 0 }
    const result = clearing(params, curve([1, 0]))
    expect(result.kind).toBe('undersubscribed')
    expect(result.k).toBeNull()
    expect(result.pStar).toBe(10n)
    expect(result.sold).toBe(8n)
    expect(result.unsold).toBe(92n)
    expect(bidderOutcome(result, 0).status).toBe('full')
  })

  it('treats a dropped bidder as refunded in full', () => {
    const params = { prices: [10n, 20n], supply: 100n, escrow: 40n, saleDecimals: 0 }
    const result = clearing(params, curve([1, 0]))
    expect(bidderOutcome(result, 1, 0)).toMatchObject({ status: 'dropped', refund: 40n, tokens: 0n })
  })

  it('agrees with the comparison the claim proof returns', () => {
    for (let seed = 1; seed <= 200; seed++) {
      const { params, bids } = random(lcg(seed))
      const result = clearing(params, curve(bids))
      for (const b of bids) {
        const direct = bidderOutcome(result, b)
        if (result.k === null) {
          expect(outcomeFromComparison(result, 2)).toEqual(direct)
        } else {
          expect(outcomeFromComparison(result, compareBid(b, result.k))).toEqual(direct)
        }
      }
    }
  })

  it('holds the sale properties on random sales', () => {
    for (let seed = 1; seed <= 2000; seed++) {
      const { params, bids } = random(lcg(seed * 7919))
      const result = clearing(params, curve(bids))
      const outcomes = allocations(result, bids)
      const unit = 10n ** BigInt(params.saleDecimals)

      // The total sold never exceeds the supply, and `sold` is the sum of the allocations.
      const sold = outcomes.reduce((sum, outcome) => sum + outcome.tokens, 0n)
      expect(sold).toBe(result.sold)
      expect(sold <= params.supply).toBe(true)
      expect(result.sold + result.unsold).toBe(params.supply)

      const proceeds = outcomes.reduce((sum, outcome) => sum + outcome.paid, 0n)
      expect(proceeds).toBe(result.proceeds)

      outcomes.forEach((outcome, i) => {
        const b = bids[i]
        // Nobody pays more than the escrow, and paid + refund is the escrow.
        expect(outcome.paid <= params.escrow).toBe(true)
        expect(outcome.paid + outcome.refund).toBe(params.escrow)
        if (outcome.tokens > 0n) {
          // One uniform price: a winner pays the ceiling of tokens * pStar / U, never above its own maximum price.
          expect(outcome.paid).toBe((outcome.tokens * result.pStar + unit - 1n) / unit)
          expect(result.pStar <= params.prices[b]).toBe(true)
        } else {
          expect(outcome.paid).toBe(0n)
        }
      })

      // A higher bid never gets a worse outcome: tokens do not decrease with `b`.
      for (let low = 0; low < params.prices.length; low++) {
        for (let high = low + 1; high < params.prices.length; high++) {
          expect(bidderOutcome(result, high).tokens >= bidderOutcome(result, low).tokens).toBe(true)
        }
      }
      // The price is within the grid: at least p_0, at most the highest step with demand.
      expect(result.pStar >= params.prices[0]).toBe(true)
      expect(result.pStar <= params.prices[params.prices.length - 1]).toBe(true)
    }
  })
})

interface Vector {
  name?: string
  prices: string[]
  supply: string
  escrow: string
  saleDecimals: number
  counts: string[]
  expect: {
    kind: string | number
    step: number
    pStar: string
    fullTokens?: string
    marginalTokens?: string
    sold?: string
    outcomes?: { b: number; cmp: 0 | 1 | 2; tokens: string; paid: string; refund: string }[]
  }
}

const vectorsPath = join(dirname(fileURLToPath(import.meta.url)), '../test-vectors/clearing.json')

describe.skipIf(!existsSync(vectorsPath))('shared vectors with the Solidity reference', () => {
  const vectors = (existsSync(vectorsPath) ? JSON.parse(readFileSync(vectorsPath, 'utf8')) : []) as Vector[]
  const kinds = ['undersubscribed', 'capped', 'uncapped']

  it('has vectors', () => {
    expect(vectors.length).toBeGreaterThan(0)
  })

  it.each(vectors.map((vector, index) => [vector.name ?? `vector ${index}`, vector] as const))('%s', (_name, vector) => {
    const params: ClearingParams = {
      prices: vector.prices.map(BigInt),
      supply: BigInt(vector.supply),
      escrow: BigInt(vector.escrow),
      saleDecimals: vector.saleDecimals,
    }
    const result = clearing(params, vector.counts.map(BigInt))
    const kind = typeof vector.expect.kind === 'number' ? kinds[vector.expect.kind] : vector.expect.kind
    expect(result.kind).toBe(kind)
    expect(result.step).toBe(vector.expect.step)
    expect(result.pStar).toBe(BigInt(vector.expect.pStar))
    if (vector.expect.fullTokens !== undefined) expect(result.full.tokens).toBe(BigInt(vector.expect.fullTokens))
    if (vector.expect.marginalTokens !== undefined) expect(result.marginal?.tokens ?? 0n).toBe(BigInt(vector.expect.marginalTokens))
    if (vector.expect.sold !== undefined) expect(result.sold).toBe(BigInt(vector.expect.sold))
    for (const outcome of vector.expect.outcomes ?? []) {
      const want = { tokens: BigInt(outcome.tokens), paid: BigInt(outcome.paid), refund: BigInt(outcome.refund) }
      expect(outcomeFromComparison(result, outcome.cmp)).toMatchObject(want)
      expect(bidderOutcome(result, outcome.b)).toMatchObject(want)
      if (result.k !== null) expect(compareBid(outcome.b, result.k)).toBe(outcome.cmp)
    }
  })
})
