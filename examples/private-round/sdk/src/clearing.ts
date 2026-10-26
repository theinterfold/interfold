// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * The settlement of a private round, a mirror of the Solidity reference (`PrivateRoundProgram`).
 * Integers only. Every bidder wants one lot of `lot` sale-token base units and accepts the price
 * steps up to its `b`. `K` is the number of lots for sale, `rho` the reserve step and `m` the
 * minimum raise. With `c_l` the number of counted bidders with `b >= l`:
 *
 * ```text
 * if c_rho < m:                     NOT_MET         everyone gets the escrow back
 * else if c_rho < K:                UNDERSUBSCRIBED price p_rho; every bidder with b >= rho gets one lot
 * else:                             SOLD_OUT        l* = max{ l >= rho : c_l >= K }, price p_{l*}
 *                                                   b > l*: one lot ("above"), b == l*: share what is left ("marginal")
 * ```
 *
 * The committee reveals only the outcome and `l*`. The contract learns how many bidders are above
 * or marginal from the claims: bidders above `l*` claim first (phase 1), the marginal bidders register in
 * phase 2, and after phase 2 each registered bidder gets `min(lot, floor(lot * R / M))`, with
 * `R = K - aboveClaimed` and `M = marginalRegistered`.
 *
 * `U = 10^saleDecimals`. A bidder pays `cost(t) = ceil(t * pStar / U)` for `t` tokens. The escrow of
 * every bidder is `ceil(lot * p_{L-1} / U)`, so `cost(lot) <= escrow` at every price.
 */
import { Outcome, type RoundOutput } from './layout'

export interface RoundSale {
  /** The price of each step (`levels` values), strictly increasing. */
  prices: readonly bigint[]
  /** The sale-token base units of one lot. */
  lot: bigint
  /** The lots for sale. */
  lots: number
  reserveStep: number
  minLots: number
  /** The decimals of the sale token: `U = 10^saleDecimals`. */
  saleDecimals: number
}

/** The tokens a bidder gets, what the bidder pays, and what is refunded. */
export interface Allocation {
  tokens: bigint
  paid: bigint
  refund: bigint
}

/** The classes of a claim. */
export type ClaimClass = 'full' | 'marginal' | 'refund'

function ceilDiv(a: bigint, b: bigint): bigint {
  return (a + b - 1n) / b
}

/** `10^saleDecimals`. */
export function saleUnit(sale: Pick<RoundSale, 'saleDecimals'>): bigint {
  return 10n ** BigInt(sale.saleDecimals)
}

/** The escrow of every bidder: the price of one lot at the highest step. */
export function escrowOf(sale: RoundSale): bigint {
  return ceilDiv(sale.lot * sale.prices[sale.prices.length - 1], saleUnit(sale))
}

/** The supply: `lots * lot`. */
export function supplyOf(sale: RoundSale): bigint {
  return sale.lot * BigInt(sale.lots)
}

/** What `tokens` sale-token base units cost at the price `pStar`. */
export function cost(tokens: bigint, pStar: bigint, saleDecimals: number): bigint {
  return ceilDiv(tokens * pStar, 10n ** BigInt(saleDecimals))
}

export interface Clearing {
  outcome: Outcome
  /** `l*` when sold out, the reserve step when undersubscribed, `null` otherwise. */
  step: number | null
  /** The price of the clearing, or 0 when nothing sells. */
  pStar: bigint
  /**
   * The step the claim proof compares the bid with, or `null` if a counted bidder needs no proof.
   * Sold out: `l*`. Undersubscribed: `reserveStep - 1` (a bidder at or above the reserve compares `2`),
   * and no proof at all when the reserve step is 0, because every bid is at or above it.
   */
  k: number | null
  /** The escrow of every bidder. */
  escrow: bigint
  /** One lot, and what a lot costs at `pStar`. */
  lot: bigint
  lotCost: bigint
}

/** The clearing from the decoded output. */
export function clearing(sale: RoundSale, output: RoundOutput): Clearing {
  const escrow = escrowOf(sale)
  const base = { outcome: output.outcome, step: output.step, escrow, lot: sale.lot }
  switch (output.outcome) {
    case Outcome.SoldOut: {
      const pStar = sale.prices[output.step as number]
      return { ...base, pStar, k: output.step, lotCost: cost(sale.lot, pStar, sale.saleDecimals) }
    }
    case Outcome.Undersubscribed: {
      const pStar = sale.prices[sale.reserveStep]
      return { ...base, pStar, k: sale.reserveStep === 0 ? null : sale.reserveStep - 1, lotCost: cost(sale.lot, pStar, sale.saleDecimals) }
    }
    default:
      return { ...base, pStar: 0n, k: null, lotCost: 0n }
  }
}

/** The claim comparison the proof returns: 0 if `b < k`, 1 if `b == k`, 2 if `b > k`. */
export function compareBid(b: number, k: number): 0 | 1 | 2 {
  return b < k ? 0 : b === k ? 1 : 2
}

/**
 * The class of a counted bidder, from the comparison `cmp` of its proof (`null` if it needs no proof).
 * Sold out: above `l*` is `full`, at `l*` is `marginal`, below is `refund`. Undersubscribed: `cmp == 2`
 * (at or above the reserve) is `full`. Not met and aborted: `refund`.
 */
export function claimClass(result: Clearing, cmp: 0 | 1 | 2 | null): ClaimClass {
  switch (result.outcome) {
    case Outcome.SoldOut:
      return cmp === 2 ? 'full' : cmp === 1 ? 'marginal' : 'refund'
    case Outcome.Undersubscribed:
      return result.k === null || cmp === 2 ? 'full' : 'refund'
    default:
      return 'refund'
  }
}

/** The claim comparison the bidder `b` has, or `null` if no proof is needed. */
export function claimComparison(result: Clearing, b: number): 0 | 1 | 2 | null {
  return result.k === null ? null : compareBid(b, result.k)
}

/** What a full winner gets: one lot at `pStar`. */
export function fullAllocation(result: Clearing): Allocation {
  return { tokens: result.lot, paid: result.lotCost, refund: result.escrow - result.lotCost }
}

/** What a bidder gets when it receives nothing: the escrow back. */
export function refundAllocation(result: Clearing): Allocation {
  return { tokens: 0n, paid: 0n, refund: result.escrow }
}

/**
 * The tokens of one marginal bidder after phase 2: `R = lots - aboveClaimed` lots are shared by
 * `marginalRegistered` bidders, and nobody gets more than one lot. `R` is at least 1: fewer than `lots`
 * bidders are above `l*`.
 */
export function marginalAllocation(sale: RoundSale, result: Clearing, aboveClaimed: number, marginalRegistered: number): Allocation {
  if (marginalRegistered === 0) return refundAllocation(result)
  const remaining = BigInt(sale.lots - aboveClaimed)
  const registered = BigInt(marginalRegistered)
  const share = registered <= remaining ? result.lot : (result.lot * remaining) / registered
  const paid = cost(share, result.pStar, sale.saleDecimals)
  return { tokens: share, paid, refund: result.escrow - paid }
}

/** The allocation of a claim of the class `cls`, after phase 2 for `marginal`. */
export function allocationOf(
  sale: RoundSale,
  result: Clearing,
  cls: ClaimClass,
  phase2: { aboveClaimed: number; marginalRegistered: number } = { aboveClaimed: 0, marginalRegistered: 0 },
): Allocation {
  switch (cls) {
    case 'full':
      return fullAllocation(result)
    case 'marginal':
      return marginalAllocation(sale, result, phase2.aboveClaimed, phase2.marginalRegistered)
    case 'refund':
      return refundAllocation(result)
  }
}

/**
 * The outcome that the program must produce for the true bids `b` of the counted bidders, in the
 * clear. The tests of the program, of the contract and of the client compare against it.
 */
export function plainOutcome(
  sale: Pick<RoundSale, 'lots' | 'minLots' | 'reserveStep'> & { levels: number },
  bids: readonly number[],
): Pick<RoundOutput, 'outcome' | 'step'> {
  const demand = (l: number) => bids.filter((b) => b >= l).length
  const { reserveStep, lots, minLots, levels } = sale
  if (demand(reserveStep) < minLots) return { outcome: Outcome.NotMet, step: null }
  if (demand(reserveStep) < lots) return { outcome: Outcome.Undersubscribed, step: reserveStep }
  let step = reserveStep
  for (let l = reserveStep; l < levels; l++) if (demand(l) >= lots) step = l
  return { outcome: Outcome.SoldOut, step }
}

/** How many bidders are above and at the clearing step, in the clear (for the tests): the sale of `claims`. */
export function plainClaims(result: Clearing, bids: readonly number[]): { above: number; marginal: number } {
  if (result.outcome !== Outcome.SoldOut || result.step === null) return { above: 0, marginal: 0 }
  const step = result.step
  return { above: bids.filter((b) => b > step).length, marginal: bids.filter((b) => b === step).length }
}
