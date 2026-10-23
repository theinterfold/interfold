// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * First-price auction as an OR of SIMD thermometers.
 *
 * Bidder `i` encrypts the slots `T_i[p] = [bid_i · n + i > p]`. Folding the index into the value
 * makes all values distinct. The program outputs `1 - ∏(1 - T_i)`, which is the thermometer of
 * the largest folded value. That output is a function of the winner and the price only.
 */

import type { Ciphertext, Evaluator } from '../evaluator'
import type { Slots } from '../field'
import type { Rng } from '../rng'
import { checkCapacity, treeDepth, type Design, type Encoded, type Layout, type PublicResult, type Setup } from './design'

/**
 * The one slot vector of bidder `index`: the thermometer of the folded value `bid · n + index`.
 *
 * ```text
 * n = 3 bidders, B = 4 levels, bidder 1 bids 2: folded = 2 · 3 + 1 = 7
 *
 *   slot p :  0 1 2 3 4 5 6 7 8 9 10 11
 *   T_1[p] :  1 1 1 1 1 1 1 0 0 0  0  0     (1 in slots 0..7, 7 ones)
 * ```
 */
export function encodeBid(setup: Setup, index: number, bid: number, _rng: Rng): Encoded {
  const folded = bid * setup.bidders + index
  const thermometer = setup.ring.onesIn([[0, folded]])
  return { plaintexts: [thermometer], secret: undefined }
}

/** The server tally: `1 - ∏(1 - T_i)`, a balanced product tree of depth `⌈log2 n⌉`. */
export function evaluate(setup: Setup, inputs: Ciphertext[][], evaluator: Evaluator): Ciphertext {
  const ones = setup.ring.constant(1)
  // below_i[p] = [folded_i <= p] = 1 - T_i[p].
  const below = inputs.map((input) => evaluator.show('1 - T_i', input[0].neg().addPlain(ones)))
  // The product is 1 where every bidder is at or below p: p is at or above the largest folded value.
  const noneAbove = evaluator.product(below)
  // 1 - product is 1 where some bidder is above p: the thermometer of the largest folded value.
  return evaluator.show('output = 1 - ∏(1 - T_i)', noneAbove.neg().addPlain(ones))
}

/**
 * Reads coefficient 0: `N · c0 = Σ slots = bid · n + winner`. The output has `largest` ones, and
 * `largest = winning bid · n + winner`.
 */
export function decode(setup: Setup, outputSlots: Slots): PublicResult {
  const coefficients = setup.ring.toCoefficients(outputSlots)
  const largest = setup.ring.slotSum(coefficients[0])
  const bidders = setup.bidders
  return { winner: largest % bidders, price: Math.floor(largest / bidders) }
}

function layout(setup: Setup): Layout {
  return {
    domain: 'slots',
    regions: [
      { name: 'folded value p = bid · n + index', start: 0, length: setup.bidders * setup.levels, width: setup.bidders, rowName: 'bid' },
    ],
    note: 'row = bid level b, column = bidder index i: slot b · n + i',
  }
}

export const firstPrice: Design = {
  name: 'first-price',
  disclosure: 'winner and winning bid, nothing else',
  priceRule: 'first',
  readout: 'reads coefficient 0: N · c0 mod t = bid · n + winner',
  inputNames: ['T_i = [folded_i > p]'],
  randomTieOrder: false,
  revealsOwnRank: false,
  depth: (bidders) => treeDepth(bidders),
  check(setup) {
    const values = setup.bidders * setup.levels
    checkCapacity(setup, values, values)
  },
  encodeBid,
  evaluate,
  decode,
  layout,
}
