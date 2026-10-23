// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * Plaintext simulation of the sealed-bid auction designs of the Rust crate in `../..`.
 *
 * Each design is one program: bidders encode their bids as slot vectors, the program tallies
 * them with slot-wise sums and products, and the result is read from the output slots. Here the
 * "ciphertexts" are the plaintext slots themselves, so every step can be printed and tested.
 * Nothing is encrypted: this is for reading and testing the encoding and the tally, not for
 * hiding bids.
 */

import { Ciphertext, Evaluator, type OpCounts, type TraceStep } from './evaluator'
import { requiredLog2q, securityLimitBits, type Profile, type Slots } from './field'
import { seededRng, shuffledIndices, type Rng } from './rng'
import { expectedResult, newSetup, ranks, setupErrors, type Design, type PublicResult, type Setup } from './designs/design'
import { firstPrice } from './designs/first-price'
import { firstPriceBlind } from './designs/first-price-blind'
import { rank } from './designs/rank'
import { rankBatched } from './designs/rank-batched'
import { rlFirstPrice } from './designs/rl-first-price'
import { rlSecondPrice } from './designs/rl-second-price'
import { secondPrice } from './designs/second-price'
import { secondPriceBlind } from './designs/second-price-blind'
import { vickrey } from './designs/vickrey'
import { vickreyCompact } from './designs/vickrey-compact'

export * from './field'
export * from './evaluator'
export * from './rng'
export * from './designs/design'
export { copies as rlSecondPriceCopies } from './designs/rl-second-price'
export { groupCount, weightBits } from './designs/ratio-common'
export {
  firstPrice,
  firstPriceBlind,
  rank,
  rankBatched,
  rlFirstPrice,
  rlSecondPrice,
  secondPrice,
  secondPriceBlind,
  vickrey,
  vickreyCompact,
}

/** A design with any secret type. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type AnyDesign = Design<any>

/** All designs in the order of the Rust summary table. The key is `Design.name`. */
export const designs: Record<string, AnyDesign> = Object.fromEntries(
  [rank, rankBatched, firstPrice, firstPriceBlind, secondPrice, secondPriceBlind, vickrey, vickreyCompact, rlFirstPrice, rlSecondPrice].map(
    (design) => [design.name, design],
  ),
)

export const designNames: string[] = Object.keys(designs)

/** The result of one simulated auction. */
export interface RunResult {
  design: AnyDesign
  setup: Setup
  bids: number[]
  /** What `decode` reads from the output. */
  result: PublicResult
  /**
   * What the rule gives on the plaintext bids, with ties broken by `setup.tiePriority`. For a
   * design with a random lane, the tie set and the winner come from the plaintext masks.
   */
  expected: PublicResult
  opCounts: OpCounts
  /** The measured multiplicative depth of the output. The Rust crate reports `design.depth(n)`. */
  depth: number
  /** The N output slots. This is what Interfold publishes. */
  outputSlots: Slots
  /** The N output coefficients: the same plaintext, as a polynomial. */
  outputCoefficients: number[]
  /** The plaintexts of each bidder, one list per bidder, one slot vector per ciphertext. */
  inputs: Slots[][]
  /** The rank that each bidder reads with its own secret, for designs that allow it. */
  ownRanks: (number | null)[] | null
  expectedRanks: number[]
  /** The steps shown by the design. `null` unless `options.trace` is set. */
  trace: TraceStep[] | null
}

export interface RunOptions {
  /** Record the intermediate values that the design shows. */
  trace?: boolean
}

/** Whether the design result and every revealed rank match the plain computation. */
export function isCorrect(run: RunResult): boolean {
  const ranksMatch = run.ownRanks === null || run.ownRanks.every((own, i) => own === run.expectedRanks[i])
  // A design with a random lane also publishes the tie set and the random value.
  const laneMatch = run.result.random === run.expected.random && run.result.tieSet?.join() === run.expected.tieSet?.join()
  return run.result.winner === run.expected.winner && run.result.price === run.expected.price && ranksMatch && laneMatch
}

/**
 * Runs one auction. A design with `randomTieOrder` gets a random tie priority from `rng`, unless
 * `tiePriority` is given. In an E3, this order comes from public randomness that is fixed after
 * the bids close. A design without `randomTieOrder` needs the identity.
 *
 * Throws a `SetupError` for an auction that the profile cannot hold, as the Rust crate does.
 * The default `rng` is `seededRng(1)`.
 */
export function run(
  design: AnyDesign | string,
  profile: Profile,
  bids: number[],
  levels: number,
  tiePriority?: number[],
  rng: Rng = seededRng(1),
  options: RunOptions = {},
): RunResult {
  const chosen = typeof design === 'string' ? designs[design] : design
  if (chosen === undefined) throw new Error(`unknown design ${design}`)
  const bidders = bids.length
  const priority = tiePriority ?? (chosen.randomTieOrder ? shuffledIndices(bidders, rng) : bids.map((_, i) => i))
  const sorted = [...priority].sort((a, b) => a - b)
  if (!sorted.every((value, i) => value === i)) {
    throw new Error(`the tie priority must be a permutation of 0..${bidders}`)
  }
  if (!chosen.randomTieOrder && !priority.every((value, i) => value === i)) {
    throw new Error(`${chosen.name} breaks ties by index`)
  }
  if (bidders < 2) throw setupErrors.tooFewBidders(bidders)
  const outOfRange = bids.findIndex((bid) => bid >= levels || bid < 0 || !Number.isInteger(bid))
  if (outOfRange >= 0) throw setupErrors.bidOutOfRange(outOfRange, bids[outOfRange], levels)
  const depth = chosen.depth(bidders)
  const limit = securityLimitBits(profile)
  if (limit !== null && requiredLog2q(depth) > limit) {
    throw setupErrors.depthTooLarge(depth, requiredLog2q(depth), limit)
  }
  const setup = newSetup(profile, bidders, levels, priority)
  chosen.check(setup)

  // Each bidder encodes its bid. The program only sees these slots, as ciphertexts.
  const encoded = bids.map((bid, index) => chosen.encodeBid(setup, index, bid, rng))
  const inputs = encoded.map((e) => e.plaintexts)
  const submissions = inputs.map((plaintexts) => plaintexts.map((slots) => new Ciphertext(setup.ring, slots)))

  const evaluator = new Evaluator(setup.ring, options.trace ?? false)
  const output = chosen.evaluate(setup, submissions, evaluator)

  const outputSlots = output.slots
  const ownRanks = chosen.revealsOwnRank ? encoded.map((e, index) => chosen.ownRank?.(setup, outputSlots, index, e.secret) ?? null) : null
  return {
    design: chosen,
    setup,
    bids,
    result: chosen.decode(setup, outputSlots),
    expected: chosen.expected?.(setup, bids, inputs) ?? expectedResult(bids, chosen.priceRule, setup.tiePriority),
    opCounts: evaluator.counts,
    depth: output.depth,
    outputSlots,
    outputCoefficients: setup.ring.toCoefficients(outputSlots),
    inputs,
    ownRanks,
    expectedRanks: chosen.expectedRanks?.(bids) ?? ranks(bids),
    trace: evaluator.trace ?? null,
  }
}
