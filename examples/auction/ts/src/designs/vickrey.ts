// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * Second-price (Vickrey) auction with 4 ct×ct products for any number of bidders. The output
 * shows the winner and the second-highest bid only. The test, the regions, and the proof that
 * the output hides everything else are in `vickrey-common.ts`.
 *
 * Inputs: the thermometers `[b ≥ p]` and `[b > p]`, and a mask (3 ciphertexts). Depth 3. A bid
 * proof shows only that the two thermometers come from one bid `b`. The mask needs no shape
 * proof.
 */

import type { Ciphertext, Evaluator } from '../evaluator'
import type { Slots } from '../field'
import type { Rng } from '../rng'
import type { Design, Encoded, PublicResult, Setup } from './design'
import { check, decodePattern, sumAll, testsUnderMask, thermometers, verifyClaim, vickreyLayout, withMask } from './vickrey-common'

/**
 * The 2 bid slot vectors `[b ≥ p]` and `[b > p]` (without the mask). They do not depend on the
 * bidder index: the program applies the index.
 *
 * ```text
 * n = 2 bidders, B = 4 levels, bid b = 2. One copy is 8 slots; the ring holds N / 8 copies.
 *
 *   slot     :  0 1 2 3 | 4 5 6 7
 *   level p  :  0 1 2 3 | 0 1 2 3
 *   [b >= p] :  1 1 1 0 | 1 1 1 0
 *   [b >  p] :  1 1 0 0 | 1 1 0 0
 *   mask     :  uniform random value in every slot (the third plaintext)
 * ```
 */
export function bidSlots(setup: Setup, bid: number): Slots[] {
  const [atLeast, above] = thermometers(setup, bid)
  return [atLeast, above]
}

/** The 3 plaintexts of one bidder: `[b ≥ p]`, `[b > p]`, and the mask. The index is not used. */
export function encodeBid(setup: Setup, _index: number, bid: number, rng: Rng): Encoded {
  return withMask(setup, bidSlots(setup, bid), rng)
}

/**
 * The server tally. The program applies the tie priority with plaintext selectors: see
 * `testsUnderMask`.
 */
export function evaluate(setup: Setup, inputs: Ciphertext[][], evaluator: Evaluator): Ciphertext {
  const bids = inputs.map((s): [Ciphertext, Ciphertext] => [s[0], s[1]])
  const masks = evaluator.show('r = Σ masks', sumAll(inputs.map((s) => s[2])))
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

export const vickrey: Design = {
  name: 'vickrey',
  disclosure: 'winner and second-highest bid, nothing else (if 1 bidder mask is honest)',
  priceRule: 'second',
  readout: 'checks a claim at 3 slot points: 3 · N multiplications mod t',
  inputNames: ['[b >= p]', '[b > p]', 'mask'],
  randomTieOrder: true,
  revealsOwnRank: false,
  depth: () => 3,
  check,
  encodeBid,
  evaluate,
  decode,
  layout: vickreyLayout,
}
