// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * Second-price with 2 ct×ct products, by blinded counting. The winning bid is public too. See
 * `blind-common.ts`.
 *
 * Region A holds the folded thermometer and region B the plain bid thermometer. With `c[p]` the
 * number of bids above slot `p`, the program computes `c · (c - 1)` in region B and `c · c` in
 * region A, then blinds the result with the sum of the masks.
 */

import type { Ciphertext, Evaluator } from '../evaluator'
import type { Slots } from '../field'
import type { Rng } from '../rng'
import { blindSubmission, checkTop, folded, split, sumAll, top } from './blind-common'
import { checkCapacity, type Design, type Encoded, type Layout, type PublicResult, type Setup } from './design'

/**
 * The 2 slot vectors of one bidder: the thermometer over both regions, and the mask.
 *
 * ```text
 * n = 3 bidders, B = 4 levels, bidder 1 bids 2: folded = 2 · 3 + 1 = 7
 *
 *                  region A (n·B = 12 slots)    region B (B = 4 slots)
 *   slot p      :  0 1 2 3 4 5 6 7 8 9 10 11    12 13 14 15
 *   thermometer :  1 1 1 1 1 1 1 0 0 0  0  0     1  1  0  0    [folded > p] in A, [bid > p] in B
 *   mask        :  uniform random value in every slot
 * ```
 */
export function encodeBid(setup: Setup, index: number, bid: number, rng: Rng): Encoded {
  const regionA = setup.bidders * setup.levels
  return blindSubmission(
    setup,
    [
      [0, folded(setup, index, bid)],
      [regionA, regionA + bid],
    ],
    rng,
  )
}

/** The server tally: `c · (c - 1 in region B) · r`. Two ct×ct products. */
export function evaluate(setup: Setup, inputs: Ciphertext[][], evaluator: Evaluator): Ciphertext {
  const regionA = setup.bidders * setup.levels
  const count = evaluator.show('c = Σ thermometers', sumAll(inputs.map((s) => s[0])))
  const blinding = evaluator.show('r = Σ masks', sumAll(inputs.map((s) => s[1])))
  // Region A: c · c, non-zero when 1 or more bids are above. Region B: c · (c - 1),
  // non-zero when 2 or more bids are above.
  const oneInB = setup.ring.onesIn([[regionA, regionA + setup.levels]])
  const selected = evaluator.show('c · (c - [region B])', evaluator.mul(count, count.subPlain(oneInB)))
  return evaluator.show('output = c · (c - [region B]) · r', evaluator.mul(selected, blinding))
}

/** Reads the top of region A (the winner) and the top of region B (the price). */
export function decode(setup: Setup, outputSlots: Slots): PublicResult {
  const regionA = setup.bidders * setup.levels
  const [winner] = split(setup, top(outputSlots, [0, regionA]))
  return { winner, price: top(outputSlots, [regionA, regionA + setup.levels]) }
}

/**
 * The check that a contract runs on a claimed result: 4 slot evaluations. The claim names the
 * winning bid as well, because the output reveals it.
 */
export function verify(setup: Setup, coefficients: number[], claim: PublicResult, winningBid: number): boolean {
  if (claim.winner === null || claim.price === null) return false
  const regionA = setup.bidders * setup.levels
  return (
    claim.winner < setup.bidders &&
    checkTop(setup, coefficients, [0, regionA], folded(setup, claim.winner, winningBid)) &&
    checkTop(setup, coefficients, [regionA, regionA + setup.levels], claim.price)
  )
}

/** The winning bid, which this design also makes public. */
export function winningBid(setup: Setup, outputSlots: Slots): number {
  return split(setup, top(outputSlots, [0, setup.bidders * setup.levels]))[1]
}

function layout(setup: Setup): Layout {
  const regionA = setup.bidders * setup.levels
  return {
    domain: 'slots',
    regions: [
      { name: 'region A: folded value p = bid · n + index', start: 0, length: regionA, width: setup.bidders, rowName: 'bid' },
      { name: 'region B: level p', start: regionA, length: setup.levels, width: setup.levels },
    ],
    note: 'region A: row = bid level b, column = bidder index i. Each region reads as a non-zero prefix.',
  }
}

export const secondPriceBlind: Design = {
  name: 'second-price-blind',
  disclosure: 'winner, second-highest bid, and winning bid (if 1 bidder mask is honest)',
  priceRule: 'second',
  readout: 'checks a claim at 4 slot points: 4 · N multiplications mod t',
  inputNames: ['thermometer', 'mask'],
  randomTieOrder: false,
  revealsOwnRank: false,
  depth: () => 2,
  check(setup) {
    const regionA = setup.bidders * setup.levels
    checkCapacity(setup, regionA + setup.levels, setup.bidders)
  },
  encodeBid,
  evaluate,
  decode,
  layout,
}
