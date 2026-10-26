// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { describe, expect, it } from 'vitest'
import {
  allocationOf,
  claimClass,
  claimComparison,
  clearing,
  compareBid,
  cost,
  escrowOf,
  plainClaims,
  plainOutcome,
  type RoundSale,
  supplyOf,
} from './clearing'
import { decodeRound, evenPrices, MAX_BIDDERS, Outcome, outputSlotsFor, type RoundParams } from './layout'

const SALE: RoundSale = {
  prices: evenPrices(100n, 50n, 8), // 100, 150, ..., 450
  lot: 1_000_000n,
  lots: 3,
  reserveStep: 2,
  minLots: 2,
  saleDecimals: 6,
}

const params = (sale: RoundSale): RoundParams => ({
  levels: sale.prices.length,
  reserveStep: sale.reserveStep,
  lots: sale.lots,
  minLots: sale.minLots,
})

/** The clearing of the true bids, through the output slots and the decoder. */
function clearBids(sale: RoundSale, bids: readonly number[]) {
  const versions = Array.from({ length: MAX_BIDDERS }, (_, i) => (i < bids.length ? 1 : 0))
  const plain = plainOutcome({ ...sale, levels: sale.prices.length }, bids)
  const slots = outputSlotsFor(
    params(sale),
    versions,
    plain.outcome as Outcome.NotMet | Outcome.Undersubscribed | Outcome.SoldOut,
    plain.step ?? undefined,
  )
  return clearing(sale, decodeRound(slots, params(sale)))
}

describe('amounts', () => {
  it('escrows the price of one lot at the highest step and supplies lots times lot', () => {
    expect(escrowOf(SALE)).toBe(450n)
    expect(supplyOf(SALE)).toBe(3_000_000n)
  })

  it('rounds the cost up', () => {
    expect(cost(1_000_000n, 101n, 6)).toBe(101n)
    expect(cost(1n, 101n, 6)).toBe(1n)
    expect(cost(0n, 101n, 6)).toBe(0n)
  })
})

describe('plain outcome', () => {
  it('is not met below the minimum raise at the reserve', () => {
    expect(plainOutcome({ ...SALE, levels: 8 }, [7, 1, 0])).toEqual({ outcome: Outcome.NotMet, step: null })
  })

  it('is undersubscribed when the reserve is met but fewer than all lots are taken', () => {
    expect(plainOutcome({ ...SALE, levels: 8 }, [7, 2, 0])).toEqual({ outcome: Outcome.Undersubscribed, step: 2 })
  })

  it('sells out at the highest step where the demand covers the lots', () => {
    expect(plainOutcome({ ...SALE, levels: 8 }, [7, 5, 5, 4, 2])).toEqual({ outcome: Outcome.SoldOut, step: 5 })
    expect(plainOutcome({ ...SALE, levels: 8 }, [7, 7, 7, 4, 2])).toEqual({ outcome: Outcome.SoldOut, step: 7 })
  })
})

describe('clearing', () => {
  it('prices a sell-out at the clearing step', () => {
    const result = clearBids(SALE, [7, 5, 5, 4, 2])
    expect(result).toMatchObject({ outcome: Outcome.SoldOut, step: 5, pStar: 350n, k: 5, lotCost: 350n, escrow: 450n })
  })

  it('prices an undersubscribed round at the reserve and compares against the step below', () => {
    const result = clearBids(SALE, [7, 2, 0])
    expect(result).toMatchObject({ outcome: Outcome.Undersubscribed, step: 2, pStar: 200n, k: 1, lotCost: 200n })
  })

  it('needs no claim proof when the reserve step is 0 and the round is undersubscribed', () => {
    const sale = { ...SALE, reserveStep: 0, minLots: 1 }
    const result = clearBids(sale, [3, 0])
    expect(result.k).toBeNull()
    expect(claimClass(result, claimComparison(result, 0))).toBe('full')
  })

  it('refunds when the reserve is not met', () => {
    const result = clearBids(SALE, [7, 1, 0])
    expect(result).toMatchObject({ outcome: Outcome.NotMet, pStar: 0n, k: null })
    expect(allocationOf(SALE, result, 'refund')).toEqual({ tokens: 0n, paid: 0n, refund: 450n })
  })

  it('treats an aborted output like a failed reserve', () => {
    const result = clearing(SALE, { counted: 0, versions: [], outcome: Outcome.Aborted, step: null, reason: 'x' })
    expect(result).toMatchObject({ pStar: 0n, k: null })
    expect(claimClass(result, null)).toBe('refund')
  })
})

describe('claims', () => {
  it('compares the bid with the claim step', () => {
    expect(compareBid(3, 5)).toBe(0)
    expect(compareBid(5, 5)).toBe(1)
    expect(compareBid(6, 5)).toBe(2)
  })

  it('classes bidders of a sell-out as above, marginal and below', () => {
    const bids = [7, 5, 5, 4, 2]
    const result = clearBids(SALE, bids)
    const classes = bids.map((b) => claimClass(result, claimComparison(result, b)))
    expect(classes).toEqual(['full', 'marginal', 'marginal', 'refund', 'refund'])
    expect(plainClaims(result, bids)).toEqual({ above: 1, marginal: 2 })
  })

  it('pays a full winner one lot at the clearing price and refunds the rest of the escrow', () => {
    const result = clearBids(SALE, [7, 5, 5, 4, 2])
    expect(allocationOf(SALE, result, 'full')).toEqual({ tokens: 1_000_000n, paid: 350n, refund: 100n })
  })

  it('shares the remaining lots among the registered marginal bidders, at most one lot each', () => {
    const result = clearBids(SALE, [7, 5, 5, 5, 2])
    // 3 lots, 1 above: 2 lots for 3 marginal bidders.
    expect(allocationOf(SALE, result, 'marginal', { aboveClaimed: 1, marginalRegistered: 3 })).toEqual({
      tokens: 666_666n,
      paid: 234n, // ceil(666666 * 350 / 10^6)
      refund: 216n,
    })
    // Two registered: a lot each.
    expect(allocationOf(SALE, result, 'marginal', { aboveClaimed: 1, marginalRegistered: 2 }).tokens).toBe(1_000_000n)
    // An above bidder that forfeits leaves a lot for the marginal bidders.
    expect(allocationOf(SALE, result, 'marginal', { aboveClaimed: 0, marginalRegistered: 3 }).tokens).toBe(1_000_000n)
  })

  it('refunds a marginal bidder when nobody registers', () => {
    const result = clearBids(SALE, [7, 5, 5, 5, 2])
    expect(allocationOf(SALE, result, 'marginal', { aboveClaimed: 1, marginalRegistered: 0 })).toEqual({
      tokens: 0n,
      paid: 0n,
      refund: 450n,
    })
  })

  it('gives every bidder at or above the reserve a lot when undersubscribed', () => {
    const bids = [7, 2, 1]
    const result = clearBids(SALE, bids)
    const classes = bids.map((b) => claimClass(result, claimComparison(result, b)))
    expect(classes).toEqual(['full', 'full', 'refund'])
    expect(allocationOf(SALE, result, 'full')).toEqual({ tokens: 1_000_000n, paid: 200n, refund: 250n })
  })
})

describe('invariants on random rounds', () => {
  it('never sells more than the supply and never charges more than the escrow', () => {
    let seed = 12345
    const next = (n: number) => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff
      return seed % n
    }
    for (let trial = 0; trial < 500; trial++) {
      const levels = 2 + next(15)
      const lots = 1 + next(12)
      const sale: RoundSale = {
        prices: evenPrices(10n, 7n, levels),
        lot: 1000n,
        lots,
        reserveStep: next(levels),
        minLots: 1 + next(lots),
        saleDecimals: 3,
      }
      const bids = Array.from({ length: 1 + next(MAX_BIDDERS) }, () => next(levels))
      const result = clearBids(sale, bids)
      const { above, marginal } = plainClaims(result, bids)
      let tokens = 0n
      for (const b of bids) {
        const cls = claimClass(result, claimComparison(result, b))
        const allocation = allocationOf(sale, result, cls, { aboveClaimed: above, marginalRegistered: marginal })
        expect(allocation.paid + allocation.refund).toBe(result.escrow)
        tokens += allocation.tokens
      }
      expect(tokens).toBeLessThanOrEqual(supplyOf(sale))
      if (result.outcome === Outcome.SoldOut) {
        // A sell-out hands out all lots, up to the rounding of the shares.
        expect(tokens).toBeGreaterThan(supplyOf(sale) - BigInt(marginal))
      }
    }
  })
})
