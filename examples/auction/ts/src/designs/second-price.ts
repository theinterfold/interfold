// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * Second-price (Vickrey) auction with a masked readout.
 *
 * The slots have two regions:
 *
 * - Region A, `0..n·B`: the folded thermometer of `bid · n + index`. The program finds the slot
 *   of the largest folded value and tags it with the index of its owner.
 * - Region B, `n·B..(n+1)·B`: the plain bid thermometer. The program keeps the slots where two
 *   or more bids are above the slot, which is the thermometer of the second-highest bid.
 *
 * Coefficient 0 of the output is `N⁻¹ · (n · second_price + winner)`. The other coefficients
 * hold the bid ladders, so each bidder also submits a mask that is uniform except for a zero at
 * coefficient 0. One honest mask makes all of those coefficients uniform.
 */

import type { Ciphertext, Evaluator } from '../evaluator'
import type { Slots } from '../field'
import { uniformSlots, type Rng } from '../rng'
import { checkCapacity, treeDepth, type Design, type Encoded, type Layout, type PublicResult, type Setup } from './design'

/**
 * The 3 slot vectors of one bidder: the ladder, the shifted ladder, and the mask.
 *
 * ```text
 * n = 3 bidders, B = 4 levels, bidder 1 bids 2: folded = 2 · 3 + 1 = 7, region A = slots 0..12
 *
 *                 region A (n·B = 12 slots)    region B (B = 4 slots)
 *   slot       :  0 1 2 3 4 5 6 7 8 9 10 11    12 13 14 15
 *   ladder     :  1 1 1 1 1 1 1 0 0 0  0  0     1  1  0  0    [folded > p] in A, [bid > p] in B
 *   shifted    :  1 1 1 1 1 1 0 0 0 0  0  0     0  0  0  0    [folded - 1 > p] in A
 *   mask       :  uniform random slots, built from a polynomial with coefficient 0 = 0
 * ```
 *
 * The own slot of the bidder is `ladder - shifted`: 1 at slot `folded - 1` only.
 */
export function encodeBid(setup: Setup, index: number, bid: number, rng: Rng): Encoded {
  const ring = setup.ring
  const regionA = setup.bidders * setup.levels
  const folded = bid * setup.bidders + index
  const ladder = ring.onesIn([
    [0, folded],
    [regionA, regionA + bid],
  ])
  const shifted = ring.onesIn([[0, Math.max(folded - 1, 0)]])
  // A uniform polynomial with coefficient 0 = 0. Its slots sum to 0.
  const maskCoefficients = uniformSlots(ring.degree, ring.t, rng)
  maskCoefficients[0] = 0
  const mask = ring.toSlots(maskCoefficients)
  return { plaintexts: [ladder, shifted, mask], secret: undefined }
}

/** The server tally, step by step. */
export function evaluate(setup: Setup, inputs: Ciphertext[][], evaluator: Evaluator): Ciphertext {
  const ring = setup.ring
  const n = setup.bidders
  const levels = setup.levels
  const regionA = n * levels
  const ones = ring.constant(1)
  const ladders = inputs.map((s) => s[0])
  const below = ladders.map((x) => x.neg().addPlain(ones))
  const belowShifted = inputs.map((s) => s[1].neg().addPlain(ones))

  // Region B: [two or more bids > p] = 1 - [no bid > p] - [exactly one bid > p].
  const [noneAbove, exactlyOne] = evaluator.productAndExactlyOne(below, ladders)
  const twoOrMore = evaluator.show('two or more bids above', noneAbove.neg().addPlain(ones).sub(exactlyOne))
  const weights = ring.zeros()
  weights.fill(n, regionA, regionA + levels)
  let output = evaluator.show('region B: n · [two or more above]', evaluator.mulPlain(twoOrMore, weights))

  // Region A: one-hot of the largest folded value, then tagged with the owner's index.
  const top = evaluator.show('region A: one-hot of the largest folded value', evaluator.product(belowShifted).sub(noneAbove))
  inputs.forEach((input, index) => {
    // Bidder 0 adds 0, so the program skips it.
    if (index === 0) return
    const ownSlot = input[0].sub(input[1])
    const owned = evaluator.mul(ownSlot, top)
    const tag = ring.zeros()
    tag.fill(index, 0, regionA)
    output = output.add(evaluator.mulPlain(owned, tag))
  })
  evaluator.show('output before the masks', output)

  for (const input of inputs) output = output.add(input[2])
  return evaluator.show('output = sum with masks', output)
}

/** Reads coefficient 0: `N · c0 = n · second_price + winner`. */
export function decode(setup: Setup, outputSlots: Slots): PublicResult {
  const coefficients = setup.ring.toCoefficients(outputSlots)
  const value = setup.ring.slotSum(coefficients[0])
  const bidders = setup.bidders
  return { winner: value % bidders, price: Math.floor(value / bidders) }
}

function layout(setup: Setup): Layout {
  const regionA = setup.bidders * setup.levels
  return {
    domain: 'slots',
    regions: [
      { name: 'region A: folded value p = bid · n + index', start: 0, length: regionA, width: setup.bidders, rowName: 'bid' },
      { name: 'region B: level p', start: regionA, length: setup.levels, width: setup.levels },
    ],
    note: 'region A: row = bid level b, column = bidder index i. The sum of ALL slots is N · c0.',
  }
}

export const secondPrice: Design = {
  name: 'second-price',
  disclosure: 'winner and second-highest bid, nothing else (if 1 bidder mask is honest)',
  priceRule: 'second',
  readout: 'reads coefficient 0: N · c0 mod t = second_price · n + winner',
  inputNames: ['ladder', 'shifted ladder', 'mask'],
  randomTieOrder: false,
  revealsOwnRank: false,
  depth: (bidders) => treeDepth(bidders) + 1,
  check(setup) {
    const regionA = setup.bidders * setup.levels
    checkCapacity(setup, regionA + setup.levels, regionA)
  },
  encodeBid,
  evaluate,
  decode,
  layout,
}
