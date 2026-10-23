// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * Shared by `first-price-blind` and `second-price-blind`: auctions by blinded counting, with a
 * fixed number of ct×ct products for any number of bidders.
 *
 * Each bidder submits a SIMD thermometer and a uniform SIMD mask. The program adds the
 * thermometers, which gives `c[p]`, the number of bids above slot `p`. It adds the masks, which
 * gives `r`, uniform when 1 mask is honest. Because `t` is prime, `f(c)[p] · r[p]` is 0 when
 * `f(c)[p] = 0` and a uniform non-zero value otherwise. The output shows only where a slot test
 * is zero.
 *
 * The result is a zero pattern, not a value in coefficient 0. A contract checks a claimed result
 * by evaluating the published plaintext at 2 slot points for each region (N multiplications mod
 * t each). A slot where `r[p] = 0` reads as zero by error, with probability `1/t`.
 */

import type { Ciphertext } from '../evaluator'
import type { Range } from '../field'
import { uniformSlots, type Rng } from '../rng'
import type { Encoded, Setup } from './design'

/** `Σ cts`. */
export function sumAll(cts: Ciphertext[]): Ciphertext {
  return cts.reduce((acc, ct) => acc.add(ct))
}

/** The thermometer and the mask of one bidder. The thermometer is 1 in the slots of `ladder`. */
export function blindSubmission(setup: Setup, ladder: Range[], rng: Rng): Encoded {
  const ring = setup.ring
  const mask = uniformSlots(ring.degree, ring.t, rng)
  return { plaintexts: [ring.onesIn(ladder), mask], secret: undefined }
}

/** The length of the non-zero prefix of `region`: the top of the thermometer in that region. */
export function top(slotValues: number[], region: Range): number {
  for (let p = region[1] - 1; p >= region[0]; p--) {
    if (slotValues[p] !== 0) return p + 1 - region[0]
  }
  return 0
}

/**
 * What a contract checks for a claimed top `value` of `region`: the slot below is non-zero and
 * the slot at `value` is zero. Each check evaluates the plaintext at one slot point.
 */
export function checkTop(setup: Setup, coefficients: number[], region: Range, value: number): boolean {
  const ring = setup.ring
  const points = ring.slotPoints()
  const at = (slot: number) => ring.evaluate(coefficients, points[slot])
  const belowIsSet = value === 0 || at(region[0] + value - 1) !== 0
  const atIsClear = region[0] + value >= region[1] || at(region[0] + value) === 0
  return belowIsSet && atIsClear
}

/** The folded value of a bid: `bid · n + index`. All folded values are distinct. */
export function folded(setup: Setup, index: number, bid: number): number {
  return bid * setup.bidders + index
}

/** The inverse of `folded`: `(index, bid)`. */
export function split(setup: Setup, foldedValue: number): [index: number, bid: number] {
  return [foldedValue % setup.bidders, Math.floor(foldedValue / setup.bidders)]
}
