// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * The two-round probe search for the clearing step, a mirror of `contracts/libraries/ProbeSearch.sol`.
 * `F[l]` is the sum of the budgets (budget units) of the counted bids with step `>= l`. The committee reveals `F`
 * at a few levels only. Round 1 reveals `F` at the coarse levels `P1`; it brackets the clearing step in `(lo, hi)`.
 * Round 2 reveals `F` strictly inside the bracket (and at level 0 when `lo == 0`) and fixes the step `lstar`.
 * `over(m)` is the over-demand test `F[m] * budgetUnit * U > p[m-1] * S`; a valid output has `over(m)` true for
 * `m <= lstar` and false after it (`over(0)` is true and `over(levels)` is false).
 */
import { LEVELS_MAX } from './layout'

/** The price grid and the sizes of a sale, as the probe search and the clearing read them. */
export interface Grid {
  /** The price of each step (`levels` values), strictly increasing: payment-token base units per `10^saleDecimals`. */
  prices: readonly bigint[]
  /** The supply `S` in sale-token base units. */
  supply: bigint
  /** Payment-token base units of one budget unit. */
  budgetUnit: bigint
  /** The decimals of the sale token: `U = 10^saleDecimals`. */
  saleDecimals: number
}

/** `U = 10^saleDecimals`: the sale-token base units of one whole sale token. */
export const saleUnitOf = (grid: Grid): bigint => 10n ** BigInt(grid.saleDecimals)

/** The revealed sums: `F[l]` (budget units) at the known levels, 0 elsewhere. 16 entries. */
export type Sums = readonly bigint[]

/** Level `m` is a probe of round 1 when `m` is a multiple of `ceil(levels / 4)` in `1..levels-1`. Bit `m` of the mask. */
export function coarseProbeMask(levels: number): number {
  const g = Math.ceil(levels / 4)
  let mask = 0
  for (let m = g; m < levels; m += g) mask |= 1 << m
  return mask
}

/** The over-demand test at level `m >= 1` for the budget sum `f`. */
export function overDemand(grid: Grid, m: number, f: bigint): boolean {
  return f * grid.budgetUnit * saleUnitOf(grid) > grid.prices[m - 1] * grid.supply
}

const has = (mask: number, m: number): boolean => (mask & (1 << m)) !== 0

export interface Round1 {
  /** False when the sums are not a monotone demand curve: the sale aborts. */
  valid: boolean
  /** The highest probe with over-demand, 0 if none. */
  lo: number
  /** The lowest probe above `lo`, `levels` if none. */
  hi: number
  /** The levels of round 2: `lo < m < hi`, and 0 when `lo == 0`. */
  probeMask2: number
}

const INVALID_ROUND1: Round1 = { valid: false, lo: 0, hi: 0, probeMask2: 0 }

/** Round 1. `sums` holds `F[m]` for the levels of `coarseProbeMask(levels)`. */
export function searchRound1(grid: Grid, sums: Sums): Round1 {
  const levels = grid.prices.length
  const mask1 = coarseProbeMask(levels)
  let previous: bigint | null = null
  let lo = 0
  for (let m = 1; m < levels; m++) {
    if (!has(mask1, m)) continue
    if (previous !== null && sums[m] > previous) return INVALID_ROUND1
    previous = sums[m]
    if (overDemand(grid, m, sums[m])) lo = m
  }
  let hi = levels
  for (let m = 1; m < levels; m++) {
    if (!has(mask1, m)) continue
    if (overDemand(grid, m, sums[m]) !== m <= lo) return INVALID_ROUND1
    if (m > lo && m < hi) hi = m
  }
  let probeMask2 = 0
  for (let m = lo + 1; m < hi; m++) probeMask2 |= 1 << m
  if (lo === 0) probeMask2 |= 1
  return { valid: true, lo, hi, probeMask2 }
}

export interface Round2 {
  /** False when the merged sums are not non-increasing, or `over` is not a prefix over the levels of round 2. */
  valid: boolean
  /** The clearing step: the highest level with over-demand, at least `lo`. */
  lstar: number
  /** `F` at the known levels (rounds 1 and 2), 0 elsewhere. 16 entries. */
  sums: bigint[]
}

/** Round 2. `sums1` holds `F` at the levels of round 1, `sums2` at the levels of `probeMask2`. */
export function searchRound2(grid: Grid, sums1: Sums, sums2: Sums, lo: number, probeMask2: number): Round2 {
  const levels = grid.prices.length
  const mask1 = coarseProbeMask(levels)
  const merged = new Array<bigint>(LEVELS_MAX).fill(0n)
  let previous: bigint | null = null
  let lstar = lo
  for (let m = 0; m < levels; m++) {
    if (has(mask1, m)) merged[m] = sums1[m]
    else if (has(probeMask2, m)) merged[m] = sums2[m]
    else continue
    if (previous !== null && merged[m] > previous) return { valid: false, lstar: 0, sums: merged }
    previous = merged[m]
    if (m > 0 && has(probeMask2, m) && overDemand(grid, m, merged[m])) lstar = m
  }
  for (let m = 1; m < levels; m++) {
    if (!has(probeMask2, m)) continue
    if (overDemand(grid, m, merged[m]) !== m <= lstar) return { valid: false, lstar: 0, sums: merged }
  }
  return { valid: true, lstar, sums: merged }
}
