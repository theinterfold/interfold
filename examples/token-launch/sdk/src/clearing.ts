// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * The clearing of a sealed token launch from the revealed budget sums, a mirror of
 * `contracts/libraries/SaleClearing.sol`. Integers only (`bigint`). `F[l]` is the budget sum of the counted bids
 * with step `>= l` in budget units; `Fb[l] = F[l] * budgetUnit`; `S` is the supply and `U = 10^saleDecimals`.
 *
 * ```text
 * lstar >= 1:  capped iff Fb[lstar] * U >= p[lstar] * S, else uncapped
 * lstar == 0:  capped iff Fb[0] * U >= p[0] * S, else undersubscribed
 * capped at s: pStar = p[s]; above = Fb[s+1] (0 if s+1 == levels); R = S - floor(above * U / pStar);
 *              step b > s gets floor(Bb * U / pStar); b < s gets 0; sold = S; the bids at b == s share R first
 *              bid first, over the claims that registered (`marginalFills`):
 *              fill_i = min(floor(Bb_i * U / pStar), what is left of R)
 * uncapped at l: pStar = ceil(Fb[l] * U / S); b >= l gets floor(Bb * U / pStar); sold = floor(Fb[l] * U / pStar)
 * undersubscribed: pStar = p[0]; everybody gets floor(Bb * U / p[0]); sold = floor(Fb[0] * U / p[0])
 * paid = ceil(tokens * pStar / U) (at most Bb); refund = escrow - paid; a loser has tokens = paid = 0
 * ```
 *
 * `Bb = B * budgetUnit` is the budget of a bid in payment-token base units. The claim proof compares the bid step
 * `b` with the clearing step `k`: `cmp` is 0 if `b < k`, 1 if `b == k`, 2 if `b > k`.
 */
import { type Grid, saleUnitOf } from './probes'

/** `kind` of the clearing, as the contract stores it. */
export const KIND_UNDERSUBSCRIBED = 0
export const KIND_CAPPED = 1
export const KIND_UNCAPPED = 2

export interface Clearing {
  /** `KIND_UNDERSUBSCRIBED`, `KIND_CAPPED` or `KIND_UNCAPPED`. */
  kind: number
  /** The step `k` of the claim proof: `s` (capped), `l` (uncapped), 0 (undersubscribed). */
  step: number
  /** The uniform price: payment-token base units per `10^saleDecimals` sale-token base units. */
  pStar: bigint
  /** The sale-token base units sold in total. It never exceeds the supply. */
  sold: bigint
  /** `R` (capped only): the sale tokens that the bids at step `s` share, first bid first. 0 otherwise. */
  remaining: bigint
}

/**
 * Clears the sale. `sums` is `Round2.sums` of the probe search: `F` at the known levels. The levels `lstar` and
 * `lstar + 1` (when below `levels`) must be known, and level 0 when `lstar == 0`.
 */
export function clearSale(grid: Grid, lstar: number, sums: readonly bigint[]): Clearing {
  const levels = grid.prices.length
  const s = grid.supply
  const u = saleUnitOf(grid)
  const here = sums[lstar] * grid.budgetUnit
  if (lstar === 0 && here * u < grid.prices[0] * s) {
    const pStar = grid.prices[0]
    return { kind: KIND_UNDERSUBSCRIBED, step: 0, pStar, sold: (here * u) / pStar, remaining: 0n }
  }
  if (here * u >= grid.prices[lstar] * s) {
    const pStar = grid.prices[lstar]
    const above = lstar + 1 === levels ? 0n : sums[lstar + 1] * grid.budgetUnit
    return { kind: KIND_CAPPED, step: lstar, pStar, sold: s, remaining: s - (above * u) / pStar }
  }
  const pStar = (here * u + s - 1n) / s
  return { kind: KIND_UNCAPPED, step: lstar, pStar, sold: (here * u) / pStar, remaining: 0n }
}

/** The comparison of the bid step `b` with the clearing step `k` that the claim proof publishes. */
export function compareStep(b: number, k: number): 0 | 1 | 2 {
  return b < k ? 0 : b === k ? 1 : 2
}

/** What a claim pays: the tokens, the price paid in payment-token base units, and the refund of the escrow. */
export interface ClaimAmounts {
  tokens: bigint
  paid: bigint
  refund: bigint
}

/**
 * The payout of an immediate claim with the comparison `cmp`, the budget `budgetUnits` and the escrow tier
 * `escrowUnits` (the public inputs of the claim proof; `budgetUnits` is 0 when `cmp` is 0). A bid at the clearing
 * step of a capped sale (`cmp == 1`) gets nothing here: it is the claim after the marginal window, which refunds the
 * escrow. Inside the window it registers, and `marginalFills` gives its payout.
 */
export function claimAmounts(
  grid: Grid,
  clearing: Clearing,
  { cmp, budgetUnits, escrowUnits }: { cmp: 0 | 1 | 2; budgetUnits: number | bigint; escrowUnits: number | bigint },
): ClaimAmounts {
  const u = saleUnitOf(grid)
  const marginal = cmp === 1 && clearing.kind === KIND_CAPPED
  const tokens = cmp === 0 || marginal ? 0n : (BigInt(budgetUnits) * grid.budgetUnit * u) / clearing.pStar
  const paid = (tokens * clearing.pStar + u - 1n) / u
  return { tokens, paid, refund: BigInt(escrowUnits) * grid.budgetUnit - paid }
}

/** A marginal claim that registered: the bid index, its budget and its escrow tier (budget units). */
export interface MarginalClaim {
  index: number
  budgetUnits: number | bigint
  escrowUnits: number | bigint
}

/**
 * The payout of the registered marginal claims of a capped sale, first bid first: each gets
 * `min(floor(Bb * U / pStar), what is left of R)` tokens, pays `ceil(tokens * pStar / U)` and is refunded the rest of
 * its escrow. Returns the amounts in the order of `claims`. `payMarginal` computes the same for one index.
 */
export function marginalFills(grid: Grid, clearing: Clearing, claims: readonly MarginalClaim[]): ClaimAmounts[] {
  const u = saleUnitOf(grid)
  const byIndex = claims.map((claim, position) => ({ claim, position })).sort((a, b) => a.claim.index - b.claim.index)
  let left = clearing.remaining
  const amounts = new Array<ClaimAmounts>(claims.length)
  for (const { claim, position } of byIndex) {
    const full = (BigInt(claim.budgetUnits) * grid.budgetUnit * u) / clearing.pStar
    const tokens = full < left ? full : left
    left -= tokens
    const paid = (tokens * clearing.pStar + u - 1n) / u
    amounts[position] = { tokens, paid, refund: BigInt(claim.escrowUnits) * grid.budgetUnit - paid }
  }
  return amounts
}
