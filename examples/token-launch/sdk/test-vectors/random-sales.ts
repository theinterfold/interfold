// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * Random sales for the property tests of the clearing, shared by the Hardhat tests (the Solidity reference) and
 * the vitest tests of the SDK mirror. A seed fixes the sale, so a failure reproduces.
 */
import type { Grid } from '../src/probes'
import type { SaleBid } from '../src/simulate'

/** A small seeded generator of numbers in `[0, 1)`. */
export function lcg(seed: number): () => number {
  let state = seed >>> 0
  return () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0
    return state / 2 ** 32
  }
}

export interface RandomSale {
  grid: Grid
  bids: SaleBid[]
}

/** An integer in `[low, high]`. */
const between = (next: () => number, low: number, high: number): number => low + Math.floor(next() * (high - low + 1))

/**
 * A random sale: 8 to 16 steps, 0 to 85 bids with a budget up to its escrow tier, and a supply scaled so that
 * the sale lands in every regime (undersubscribed, uncapped, capped at any step) over many seeds.
 */
export function randomSale(next: () => number): RandomSale {
  const levels = between(next, 8, 16)
  const saleDecimals = [0, 6, 18][between(next, 0, 2)]
  const budgetUnit = BigInt([1, 100, 10_000, 1_000_000][between(next, 0, 3)])
  const prices: bigint[] = []
  let price = BigInt(between(next, 1, 5000)) * budgetUnit
  for (let l = 0; l < levels; l++) {
    prices.push(price)
    price += BigInt(between(next, 1, 3000)) * budgetUnit
  }
  const tiers = [between(next, 1, 4095), between(next, 1, 4095), between(next, 1, 4095), between(next, 1, 4095)]
  const bids: SaleBid[] = Array.from({ length: between(next, 0, 85) }, () => {
    const escrow = tiers[between(next, 0, 3)]
    // Many bids at the escrow, many small ones, so that budget digits and ties both appear.
    const budget = next() < 0.3 ? escrow : between(next, 1, escrow)
    return { step: between(next, 0, levels - 1), budget, escrow }
  })
  const unit = 10n ** BigInt(saleDecimals)
  const demand = bids.reduce((sum, bid) => sum + BigInt(bid.budget), 0n) * budgetUnit
  const [num, den] = [
    [1n, 3n],
    [1n, 2n],
    [1n, 1n],
    [3n, 2n],
    [3n, 1n],
  ][between(next, 0, 4)]
  // Sell about what `demand` buys at one of the prices, scaled by `num / den`.
  const supply = (demand * unit * num) / (den * prices[between(next, 0, levels - 1)])
  return { grid: { prices, supply: supply > 0n ? supply : 1n, budgetUnit, saleDecimals }, bids }
}
