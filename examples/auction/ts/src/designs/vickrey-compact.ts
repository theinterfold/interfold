// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * `vickrey` with one bid ciphertext instead of two. Inputs: one bid ciphertext
 * `[b ≥ p] + [b = p]` (values 0, 1, 2), and a mask (2 ciphertexts). The program squares each bid
 * ciphertext to get both thermometers: `n` more ct×ct, depth 4. The rest is `vickrey`: see
 * `vickrey-common.ts`.
 */

import type { Ciphertext, Evaluator } from '../evaluator'
import type { Slots } from '../field'
import type { Rng } from '../rng'
import type { Design, Encoded, PublicResult, Setup } from './design'
import { check, compactSlots, decodePattern, sumAll, testsUnderMask, verifyClaim, vickreyLayout, withMask } from './vickrey-common'

/**
 * The bid slot vector `v = 2 · [b ≥ p] - [b > p]` (without the mask): 1 below the bid, 2 at the
 * bid, 0 above. It does not depend on the bidder index.
 *
 * ```text
 * n = 2 bidders, B = 4 levels, bid b = 2. One copy is 8 slots; the ring holds N / 8 copies.
 *
 *   slot     :  0 1 2 3 | 4 5 6 7
 *   level p  :  0 1 2 3 | 0 1 2 3
 *   v        :  1 1 2 0 | 1 1 2 0
 *   mask     :  uniform random value in every slot (the second plaintext)
 * ```
 */
export function bidSlots(setup: Setup, bid: number): Slots[] {
  return [compactSlots(setup, bid)]
}

/** The 2 plaintexts of one bidder: `v` and the mask. The index is not used. */
export function encodeBid(setup: Setup, _index: number, bid: number, rng: Rng): Encoded {
  return withMask(setup, bidSlots(setup, bid), rng)
}

/** The server tally: recover both thermometers from `v`, then run the `vickrey` tests. */
export function evaluate(setup: Setup, inputs: Ciphertext[][], evaluator: Evaluator): Ciphertext {
  const half = setup.ring.constant(Math.ceil(setup.ring.t / 2))
  // With v ∈ {0, 1, 2}: [b ≥ p] = v(3 - v)/2 and [b > p] = v(2 - v).
  const bids = inputs.map((s, j): [Ciphertext, Ciphertext] => {
    const v = s[0]
    const square = evaluator.mul(v, v)
    const triple = v.add(v).add(v)
    const atLeast = evaluator.show(`bidder ${j}: [b >= p] = v(3 - v)/2`, evaluator.mulPlain(triple.sub(square), half))
    const above = evaluator.show(`bidder ${j}: [b > p] = v(2 - v)`, v.add(v).sub(square))
    return [atLeast, above]
  })
  const masks = evaluator.show('r = Σ masks', sumAll(inputs.map((s) => s[1])))
  return testsUnderMask(setup, bids, masks, evaluator)
}

/** Reads the zero pattern: the winner region is clear at the price level `s`. */
export function decode(setup: Setup, outputSlots: Slots): PublicResult {
  return decodePattern(setup, outputSlots)
}

/** The check that a contract runs on a claimed result. See `verifyClaim`. */
export function verify(setup: Setup, coefficients: number[], claim: PublicResult): boolean {
  return verifyClaim(setup, coefficients, claim)
}

export const vickreyCompact: Design = {
  name: 'vickrey-compact',
  disclosure: 'winner and second-highest bid, nothing else (if 1 bidder mask is honest)',
  priceRule: 'second',
  readout: 'checks a claim at 3 slot points: 3 · N multiplications mod t',
  inputNames: ['v = [b >= p] + [b = p]', 'mask'],
  randomTieOrder: true,
  revealsOwnRank: false,
  depth: () => 4,
  check,
  encodeBid,
  evaluate,
  decode,
  layout: vickreyLayout,
}
