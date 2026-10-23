// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * Rank scores with bids in the exponent. The depth is 2 for any number of bidders.
 *
 * Bidder `i` submits `X^b`, `X^-b`, a secret blinding `ρ ≠ 0`, and a mask. The product
 * `X^b_i · X^-b_j · Σ_k X^-k` has a 1 in coefficient 0 exactly when `b_i ≥ b_j`, so coefficient 0
 * of `Z_i` counts the bidders that `i` beats (`W_i`). The program publishes
 * `ρ_i · (W_i - (n - 1))` at a score position for each bidder:
 *
 * - It is 0 for the winner only.
 * - For a loser it is a uniform non-zero value, because `t` is prime. Only bidder `i` knows `ρ_i`,
 *   so only bidder `i` can read its own rank.
 *
 * Each bidder owns a window of `3B` coefficients around its score position. The other
 * coefficients of the window hold `b_i - b_j`, so each bidder also submits a mask that is uniform
 * except for zeros at the score positions. The design does not compute a price: the winner
 * opens a bid commitment outside the program.
 *
 * Here the design works on coefficients. A polynomial is held by its slots, and a product of two
 * polynomials is the slot-wise product (see `field.ts`).
 */

import type { Ciphertext, Evaluator } from '../evaluator'
import { inverse, type Slots } from '../field'
import { uniformSlots, type Rng } from '../rng'
import { checkCapacity, type Design, type Encoded, type Layout, type PublicResult, type Setup } from './design'

/** What a bidder keeps after it submits: the blinding that lets it read its own rank. */
export interface RankSecret {
  blinding: number
}

function window(setup: Setup): number {
  return 3 * setup.levels
}

/** `Z_i` spans the exponents `-2B..B`, so the score sits `2B` into the window of bidder `i`. */
function scorePosition(setup: Setup, index: number): number {
  return index * window(setup) + 2 * setup.levels
}

/**
 * The coefficients of `Σ_{k=from}^{B-1} X^-k`. Coefficient 0 of `X^d` times this is `[d ≥ from]`
 * for `|d| < B`.
 */
export function step(setup: Setup, from: number): number[] {
  const { ring, levels } = setup
  const coefficients = ring.zeros()
  for (let k = from; k < levels; k++) {
    // X^0 = 1. X^-k = -X^(N-k) for k > 0, because X^N = -1.
    const [position, value] = k === 0 ? [0, 1] : [ring.degree - k, ring.t - 1]
    coefficients[position] = (coefficients[position] + value) % ring.t
  }
  return coefficients
}

/**
 * The 4 plaintexts of one bidder. They are polynomials, shown here by their coefficients (the
 * slots are the transform of these, see `Ring.toSlots`).
 *
 * ```text
 * n = 2 bidders, B = 4 levels, bid b = 2, blinding ρ = 5. Window = 3B = 12 coefficients.
 *
 *   coefficient :  0  1  2  3 ...                 N-2  N-1     (N = ring degree)
 *   X^b         :  0  0  1  0 ...                  0    0      coefficient b = 1
 *   X^-b        :  0  0  0  0 ...                 -1    0      coefficient N-b = t-1  (X^N = -1)
 *   blinding    :  5  0  0  0 ...                  0    0      coefficient 0 = ρ
 *   mask        :  uniform, except 0 at the score positions 2B = 8 and 3B + 2B = 20
 * ```
 */
export function encodeBid(setup: Setup, _index: number, bid: number, rng: Rng): Encoded<RankSecret> {
  const { ring } = setup
  const blinding = rng.range(1, ring.t)
  const blindingPolynomial = ring.zeros()
  blindingPolynomial[0] = blinding
  const mask = uniformSlots(ring.degree, ring.t, rng)
  for (let index = 0; index < setup.bidders; index++) mask[scorePosition(setup, index)] = 0
  const plaintexts = [ring.monomial(bid), ring.monomial(-bid), blindingPolynomial, mask].map((c) => ring.toSlots(c))
  return { plaintexts, secret: { blinding } }
}

/** The server tally, step by step. */
export function evaluate(setup: Setup, inputs: Ciphertext[][], evaluator: Evaluator): Ciphertext {
  const { ring } = setup
  const n = setup.bidders
  // Bidder i beats a lower index on a tie (≥) and loses to a higher index on a tie (>).
  const atLeast = ring.toSlots(step(setup, 0))
  const above = ring.toSlots(step(setup, 1))
  const rivalsCoefficients = ring.zeros()
  rivalsCoefficients[0] = (n - 1) % ring.t
  const rivals = ring.toSlots(rivalsCoefficients)

  // lower[i] = Σ_{j<i} X^-b_j and higher[i] = Σ_{j>i} X^-b_j, in O(n) additions.
  const lower: (Ciphertext | null)[] = new Array(n).fill(null)
  const higher: (Ciphertext | null)[] = new Array(n).fill(null)
  for (let i = 1; i < n; i++) {
    const previous = inputs[i - 1][1]
    const sum = lower[i - 1]
    lower[i] = sum === null ? previous : sum.add(previous)
  }
  for (let i = n - 2; i >= 0; i--) {
    const next = inputs[i + 1][1]
    const sum = higher[i + 1]
    higher[i] = sum === null ? next : sum.add(next)
  }

  let output: Ciphertext | null = null
  for (const [i, input] of inputs.entries()) {
    const lo = lower[i]
    const hi = higher[i]
    // Z_i = X^b_i · (Σ_{j<i} X^-b_j · Σ_{k≥0} X^-k + Σ_{j>i} X^-b_j · Σ_{k≥1} X^-k).
    let shiftedRivals: Ciphertext
    if (lo !== null && hi !== null) {
      shiftedRivals = evaluator.mulPlain(lo, atLeast).add(evaluator.mulPlain(hi, above))
    } else if (lo !== null) {
      shiftedRivals = evaluator.mulPlain(lo, atLeast)
    } else if (hi !== null) {
      shiftedRivals = evaluator.mulPlain(hi, above)
    } else {
      throw new Error('check() requires two or more bidders')
    }
    evaluator.show(`bidder ${i}: Σ_j X^-b_j · step`, shiftedRivals)
    // Coefficient 0 of this product is W_i, the number of bidders that i beats.
    const wins = evaluator.show(`bidder ${i}: Z_i = X^b_i · Σ_j X^-b_j · step`, evaluator.mul(input[0], shiftedRivals))
    // ρ_i · (W_i - (n - 1)): 0 for the winner, uniform non-zero for a loser.
    const score = evaluator.show(`bidder ${i}: ρ_i · (Z_i - (n - 1))`, evaluator.mul(wins.subPlain(rivals), input[2]))
    // Move coefficient 0 to the score position of bidder i.
    const placed = evaluator.show(
      `bidder ${i}: score placed at ${scorePosition(setup, i)}`,
      evaluator.mulPlain(score, ring.toSlots(ring.monomial(scorePosition(setup, i)))),
    )
    output = output === null ? placed : output.add(placed)
  }
  if (output === null) throw new Error('check() requires two or more bidders')
  evaluator.show('Σ placed scores', output)
  for (const input of inputs) output = output.add(input[3])
  return evaluator.show('output = scores + masks', output)
}

/** Reads the `n` score coefficients: the single zero names the winner. */
export function decode(setup: Setup, outputSlots: Slots): PublicResult {
  const coefficients = setup.ring.toCoefficients(outputSlots)
  const zeros = Array.from({ length: setup.bidders }, (_, i) => i).filter((i) => coefficients[scorePosition(setup, i)] === 0)
  return { winner: zeros.length === 1 ? zeros[0] : null, price: null }
}

/** The rank that bidder `index` reads with its blinding: `score / ρ + (n - 1)` bidders are beaten. */
export function ownRank(setup: Setup, outputSlots: Slots, index: number, secret: RankSecret): number | null {
  const { t } = setup.ring
  const n = setup.bidders
  const score = setup.ring.toCoefficients(outputSlots)[scorePosition(setup, index)]
  const beaten = (((score * inverse(secret.blinding, t)) % t) + (n - 1)) % t
  return beaten < n ? n - beaten : null
}

function layout(setup: Setup): Layout {
  return {
    domain: 'coefficients',
    regions: Array.from({ length: setup.bidders }, (_, i) => ({
      name: `window ${i} [${i * window(setup)}..${(i + 1) * window(setup)})`,
      start: i * window(setup),
      length: window(setup),
    })),
    columnName: 'offset in window',
    points: Array.from({ length: setup.bidders }, (_, i) => ({ name: `score ${i}`, index: scorePosition(setup, i) })),
    note: `coefficients, not slots. The score of bidder i is at offset 2B = ${2 * setup.levels} of window i. Coefficient N-k holds the exponent -k.`,
  }
}

export const rank: Design<RankSecret> = {
  name: 'rank',
  disclosure: 'winner only; each bidder can read its own rank (if 1 bidder mask is honest)',
  priceRule: 'none',
  readout: 'reads n score coefficients: the single zero names the winner',
  inputNames: ['X^b', 'X^-b', 'blinding ρ', 'mask'],
  randomTieOrder: false,
  revealsOwnRank: true,
  depth: () => 2,
  check(setup) {
    checkCapacity(setup, setup.bidders * window(setup), setup.bidders)
  },
  encodeBid,
  evaluate,
  decode,
  layout,
  ownRank,
}
