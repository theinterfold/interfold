// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * First-price with 1 ct×ct product, by blinded counting. See `blind-common.ts`.
 *
 * Slot `p` of the output is `c[p] · r[p]`: 0 where no bid is above `p`, and a uniform non-zero
 * value elsewhere. The length of the non-zero prefix is the largest folded value
 * `bid · n + index`, so the output shows the winner and the winning bid only.
 */

import type { Ciphertext, Evaluator } from '../evaluator'
import type { Slots } from '../field'
import type { Rng } from '../rng'
import { blindSubmission, checkTop, folded, split, sumAll, top } from './blind-common'
import { checkCapacity, type Design, type Encoded, type Layout, type PublicResult, type Setup } from './design'

/**
 * The 2 slot vectors of one bidder: the thermometer and the mask.
 *
 * ```text
 * n = 3 bidders, B = 4 levels, bidder 1 bids 2: folded = 2 · 3 + 1 = 7
 *
 *   slot p     :  0 1 2 3 4 5 6 7 8 9 10 11
 *   thermometer:  1 1 1 1 1 1 1 0 0 0  0  0     [folded > p]
 *   mask       :  uniform random value in every slot
 * ```
 */
export function encodeBid(setup: Setup, index: number, bid: number, rng: Rng): Encoded {
  return blindSubmission(setup, [[0, folded(setup, index, bid)]], rng)
}

/** The server tally: `(Σ thermometers) · (Σ masks)`. One ct×ct product. */
export function evaluate(_setup: Setup, inputs: Ciphertext[][], evaluator: Evaluator): Ciphertext {
  // c[p] = the number of bids above p.
  const count = evaluator.show('c = Σ thermometers', sumAll(inputs.map((s) => s[0])))
  // r = Σ masks: uniform when 1 mask is honest.
  const blinding = evaluator.show('r = Σ masks', sumAll(inputs.map((s) => s[1])))
  // c[p] · r[p] is 0 where c[p] = 0, and uniform non-zero elsewhere.
  return evaluator.show('output = c · r', evaluator.mul(count, blinding))
}

/** Reads the length of the non-zero prefix and splits it into the winner and the price. */
export function decode(setup: Setup, outputSlots: Slots): PublicResult {
  const [winner, price] = split(setup, top(outputSlots, [0, setup.bidders * setup.levels]))
  return { winner, price }
}

/** The check that a contract runs on a claimed result: 2 slot evaluations. */
export function verify(setup: Setup, coefficients: number[], claim: PublicResult): boolean {
  if (claim.winner === null || claim.price === null) return false
  const region: [number, number] = [0, setup.bidders * setup.levels]
  return claim.winner < setup.bidders && checkTop(setup, coefficients, region, folded(setup, claim.winner, claim.price))
}

function layout(setup: Setup): Layout {
  return {
    domain: 'slots',
    regions: [
      { name: 'folded value p = bid · n + index', start: 0, length: setup.bidders * setup.levels, width: setup.bidders, rowName: 'bid' },
    ],
    note: 'row = bid level b, column = bidder index i: slot b · n + i. A zero above a non-zero prefix is the top.',
  }
}

export const firstPriceBlind: Design = {
  name: 'first-price-blind',
  disclosure: 'winner and winning bid, nothing else (if 1 bidder mask is honest)',
  priceRule: 'first',
  readout: 'checks a claim at 2 slot points: 2 · N multiplications mod t',
  inputNames: ['thermometer [folded > p]', 'mask'],
  randomTieOrder: false,
  revealsOwnRank: false,
  depth: () => 1,
  check(setup) {
    checkCapacity(setup, setup.bidders * setup.levels, setup.bidders)
  },
  encodeBid,
  evaluate,
  decode,
  layout,
}
