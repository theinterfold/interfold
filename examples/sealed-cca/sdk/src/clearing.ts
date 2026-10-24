// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * The clearing of a sealed CCA sale, a mirror of the Solidity reference (`SealedCcaProgram`). Integers
 * only. `L` is the number of price steps, `c_l` the number of counted bidders with `b >= l` (`c_L = 0`),
 * `S` the supply, `E` the escrow of every bid and `U = 10^saleDecimals`. A bidder active at the price
 * `p` buys `E * U / p` sale-token base units.
 *
 * ```text
 * for l = L-1 down to 1:
 *     if c_l * E * U > p_{l-1} * S:           # bidders with b >= l over-demand just above p_{l-1}
 *         if c_l * E * U >= p_l * S:          # ... and still at p_l
 *             CAPPED at s = l:   pStar = p_l; full winners b > l; marginal b == l
 *         else:
 *             UNCAPPED at l:     pStar = ceil(c_l * E * U / S), in (p_{l-1}, p_l); full winners b >= l
 *         stop
 * none found:
 *     if c_0 * E * U >= p_0 * S:  CAPPED at s = 0: pStar = p_0; full b > 0; marginal b == 0
 *     else:                       UNDERSUBSCRIBED: pStar = p_0; everyone full; the unsold go back
 * ```
 *
 * A full winner gets `floor(E * U / pStar)` tokens and pays `ceil(tokens * pStar / U)` (at most `E`).
 * In the capped case with `m = c_s - c_{s+1}` marginal bidders, `R = S - c_{s+1} * fullTokens` is
 * shared: each marginal bidder gets `min(floor(R / m), fullTokens)` tokens at `pStar`.
 * The rest of `E` is refunded. A loser gets all of `E` back.
 */
import { LEVELS } from './layout'

export type ClearingKind = 'capped' | 'uncapped' | 'undersubscribed'

export interface ClearingParams {
  /** The price of each step (`levels` values), strictly increasing. */
  prices: readonly bigint[]
  /** The supply `S` in sale-token base units. */
  supply: bigint
  /** The escrow `E` of every bid in payment-token base units. */
  escrow: bigint
  /** The decimals of the sale token: `U = 10^saleDecimals`. */
  saleDecimals: number
}

/** The tokens a bidder gets, what the bidder pays, and what is refunded. */
export interface Allocation {
  tokens: bigint
  paid: bigint
  refund: bigint
}

export interface Clearing {
  kind: ClearingKind
  /** `s` when capped, `l` when uncapped, 0 when undersubscribed. */
  step: number
  /** The step the claim proof compares the bid with: `s` or `l`; `null` when undersubscribed (no proof needed). */
  k: number | null
  /** The uniform price: payment-token base units per `10^saleDecimals` sale-token base units. */
  pStar: bigint
  /** What a full winner gets. */
  full: Allocation
  /** What a marginal bidder gets (capped only); `null` otherwise. */
  marginal: Allocation | null
  /** The number of marginal bidders: `c_s - c_{s+1}` when capped. */
  marginalCount: bigint
  /** The total of sale-token base units sold, and of payment-token base units paid. */
  sold: bigint
  proceeds: bigint
  /** `S - sold`: the creator can take it back. */
  unsold: bigint
  /** The escrow of one bid, for a loser's refund. */
  escrow: bigint
}

export type OutcomeStatus = 'full' | 'marginal' | 'loser' | 'dropped'

export interface BidderOutcome extends Allocation {
  status: OutcomeStatus
}

function ceilDiv(a: bigint, b: bigint): bigint {
  return (a + b - 1n) / b
}

/**
 * The clearing from the counts `c_0..c_{L-1}` of the decrypted output (`counts` has 16 values; the
 * ones from `levels` up must be 0).
 */
export function clearing(params: ClearingParams, counts: readonly bigint[]): Clearing {
  const { prices, supply, escrow, saleDecimals } = params
  const levels = prices.length
  if (levels < 2 || levels > LEVELS) throw new Error(`levels must be in [2, ${LEVELS}], got ${levels}`)
  if (counts.length !== LEVELS) throw new Error(`counts has ${LEVELS} values, got ${counts.length}`)
  if (supply <= 0n || escrow <= 0n) throw new Error('The supply and the escrow must be positive')
  const U = 10n ** BigInt(saleDecimals)
  const demand = (l: number): bigint => (l < levels ? counts[l] : 0n)
  const eu = escrow * U
  const cost = (tokens: bigint, price: bigint): bigint => ceilDiv(tokens * price, U)

  const make = (kind: ClearingKind, step: number, pStar: bigint, above: bigint, marginalCount: bigint): Clearing => {
    // `above` bidders are full; `marginalCount` share what is left (capped only).
    const fullTokens = eu / pStar
    const fullPaid = cost(fullTokens, pStar)
    const full: Allocation = { tokens: fullTokens, paid: fullPaid, refund: escrow - fullPaid }
    let marginal: Allocation | null = null
    let sold = above * fullTokens
    let proceeds = above * fullPaid
    if (kind === 'capped') {
      const remaining = supply - above * fullTokens
      const share = marginalCount === 0n ? 0n : remaining / marginalCount
      const tokens = share < fullTokens ? share : fullTokens
      const paid = cost(tokens, pStar)
      marginal = { tokens, paid, refund: escrow - paid }
      sold += marginalCount * tokens
      proceeds += marginalCount * paid
    }
    return {
      kind,
      step,
      k: kind === 'undersubscribed' ? null : step,
      pStar,
      full,
      marginal,
      marginalCount,
      sold,
      proceeds,
      unsold: supply - sold,
      escrow,
    }
  }

  for (let l = levels - 1; l >= 1; l--) {
    const total = demand(l) * eu
    if (total > prices[l - 1] * supply) {
      if (total >= prices[l] * supply) return make('capped', l, prices[l], demand(l + 1), demand(l) - demand(l + 1))
      return make('uncapped', l, ceilDiv(total, supply), demand(l), 0n)
    }
  }
  if (demand(0) * eu >= prices[0] * supply) return make('capped', 0, prices[0], demand(1), demand(0) - demand(1))
  return make('undersubscribed', 0, prices[0], demand(0), 0n)
}

/**
 * What a bidder with the bid `b` gets. `counted` is the counted version from the output (0 or
 * `false` if the bidder was dropped); leave it out for a bidder known to be counted. A dropped bidder
 * gets the whole escrow back without a proof.
 */
export function bidderOutcome(result: Clearing, b: number, counted?: number | boolean): BidderOutcome {
  const loser: BidderOutcome = { status: 'loser', tokens: 0n, paid: 0n, refund: result.escrow }
  if (counted === 0 || counted === false) return { ...loser, status: 'dropped' }
  const full: BidderOutcome = { status: 'full', ...result.full }
  switch (result.kind) {
    case 'undersubscribed':
      return full
    case 'uncapped':
      return b >= result.step ? full : loser
    case 'capped':
      if (b > result.step) return full
      if (b === result.step && result.marginal !== null) return { status: 'marginal', ...result.marginal }
      return loser
  }
}

/** The claim comparison the proof returns: 0 if `b < k`, 1 if `b == k`, 2 if `b > k`. */
export function compareBid(b: number, k: number): 0 | 1 | 2 {
  return b < k ? 0 : b === k ? 1 : 2
}

/** The outcome for a claim with the comparison `cmp` (the proof's public output) against the clearing `k`. */
export function outcomeFromComparison(result: Clearing, cmp: 0 | 1 | 2): BidderOutcome {
  const loser: BidderOutcome = { status: 'loser', tokens: 0n, paid: 0n, refund: result.escrow }
  const full: BidderOutcome = { status: 'full', ...result.full }
  switch (result.kind) {
    case 'undersubscribed':
      return full
    case 'uncapped':
      return cmp >= 1 ? full : loser
    case 'capped':
      if (cmp === 2) return full
      if (cmp === 1 && result.marginal !== null) return { status: 'marginal', ...result.marginal }
      return loser
  }
}
