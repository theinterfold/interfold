// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * A sale run in the clear: the budget sums of the bids, the two probe rounds that reveal only some of them, the
 * clearing, and the payout of each bid. It is what the committee, the contract and the claim proofs compute
 * together, without the privacy. Tests and previews use it as the reference.
 */
import { type ClaimAmounts, type Clearing, KIND_CAPPED, claimAmounts, clearSale, compareStep, marginalFills } from './clearing'
import { LEVELS_MAX } from './layout'
import { type Grid, type Round1, type Round2, coarseProbeMask, searchRound1, searchRound2 } from './probes'

/** A counted bid: its max price step, budget and escrow tier (budget units). */
export interface SaleBid {
  step: number
  budget: number
  escrow: number
}

/** `F[l]`: the sum of the budgets of the bids with a step of at least `l`, for every level `0..LEVELS_MAX-1`. */
export function demandSums(bids: readonly SaleBid[]): bigint[] {
  return Array.from({ length: LEVELS_MAX }, (_, l) => bids.reduce((sum, bid) => (bid.step >= l ? sum + BigInt(bid.budget) : sum), 0n))
}

/** The sums that an E3 with the probe mask `mask` reveals: `sums` at the levels of the mask, 0 elsewhere. */
export function revealed(sums: readonly bigint[], mask: number): bigint[] {
  return sums.map((sum, l) => ((mask >> l) & 1 ? sum : 0n))
}

export interface Simulation {
  /** The sums of the full demand curve (never revealed). */
  full: bigint[]
  round1: Round1
  /** `null` when round 1 was invalid. */
  round2: Round2 | null
  /** `null` when a round was invalid. */
  clearing: Clearing | null
  /**
   * The payout of each bid, in the order of `bids` (the bid index); empty when the sale did not clear. The bids at the
   * clearing step of a capped sale are paid by `marginalFills`, as if every one registered in the window.
   */
  outcomes: (ClaimAmounts & { cmp: 0 | 1 | 2 })[]
}

/** Runs the sale of `bids` (all counted) on `grid`. */
export function simulateSale(grid: Grid, bids: readonly SaleBid[]): Simulation {
  const full = demandSums(bids)
  const round1 = searchRound1(grid, revealed(full, coarseProbeMask(grid.prices.length)))
  if (!round1.valid) return { full, round1, round2: null, clearing: null, outcomes: [] }
  const round2 = searchRound2(
    grid,
    revealed(full, coarseProbeMask(grid.prices.length)),
    revealed(full, round1.probeMask2),
    round1.lo,
    round1.probeMask2,
  )
  if (!round2.valid) return { full, round1, round2, clearing: null, outcomes: [] }
  const clearing = clearSale(grid, round2.lstar, round2.sums)
  const outcomes = bids.map((bid) => {
    const cmp = compareStep(bid.step, clearing.step)
    return { cmp, ...claimAmounts(grid, clearing, { cmp, budgetUnits: cmp === 0 ? 0 : bid.budget, escrowUnits: bid.escrow }) }
  })
  if (clearing.kind === KIND_CAPPED) {
    const marginal = bids.flatMap((bid, index) =>
      outcomes[index].cmp === 1 ? [{ index, budgetUnits: bid.budget, escrowUnits: bid.escrow }] : [],
    )
    marginalFills(grid, clearing, marginal).forEach((amounts, i) => Object.assign(outcomes[marginal[i].index], amounts))
  }
  return { full, round1, round2, clearing, outcomes }
}
