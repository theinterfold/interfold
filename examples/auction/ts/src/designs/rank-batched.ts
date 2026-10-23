// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * Rank scores for all bidders with 2 ct×ct products, for any number of bidders.
 *
 * Each bidder `i` places its bid in its own window: `A_i = X^(s_i + b_i)` with
 * `s_i = 3B·i + 2B`. The program multiplies `ΣA_i` by `ΣX^-b_j · Σ_k X^-k` once. Coefficient
 * `s_i` of the product is `W_i = #{j : b_j ≤ b_i}`, and the windows of width `3B` do not overlap.
 *
 * The second product applies the blinding of each bidder to its own score only:
 * `R = Σ_k ρ_k X^(3Bn·k)`. Score `i` times `ρ_k` lands at `3B(i + n·k) + 2B`, so the pairs
 * `(i, k)` never collide, and the pairs with `i = k` are the published scores
 * `ρ_i · (W_i - n)`. Bidder masks hide all other coefficients.
 *
 * Costs of the fixed depth: `3 · n² · B` coefficients, and a tie for the highest bid is public
 * (all tied bidders show a zero). Ranks are competition ranks: `1 + #{j : b_j > b_i}`.
 */

import type { Ciphertext, Evaluator } from '../evaluator'
import { inverse, type Slots } from '../field'
import { uniformSlots, type Rng } from '../rng'
import { checkCapacity, type Design, type Encoded, type Layout, type PublicResult, type Setup } from './design'
import { step, type RankSecret } from './rank'

function window(setup: Setup): number {
  return 3 * setup.levels
}

/** Where the score of bidder `index` sits before blinding. */
function windowCenter(setup: Setup, index: number): number {
  return index * window(setup) + 2 * setup.levels
}

/** Where the blinding of bidder `index` shifts its own score. */
function blindingShift(setup: Setup, index: number): number {
  return index * setup.bidders * window(setup)
}

function scorePosition(setup: Setup, index: number): number {
  return windowCenter(setup, index) + blindingShift(setup, index)
}

/**
 * The 4 plaintexts of one bidder. They are polynomials, shown here by their coefficients (the
 * slots are the transform of these, see `Ring.toSlots`).
 *
 * ```text
 * n = 2 bidders, B = 4 levels, bidder i = 1 bids b = 2, blinding ρ = 5.
 * Window = 3B = 12. Window center s_1 = 12 + 8 = 20. Blinding shift = 1 · n · 12 = 24.
 *
 *   coefficient :  0 ...  22 ...  24 ... N-2 N-1
 *   X^(s+b)     :  0 ...   1 ...   0 ...  0   0     coefficient s_1 + b = 22
 *   X^-b        :  0 ...   0 ...   0 ... -1   0     coefficient N-b
 *   blinding    :  0 ...   0 ...   5 ...  0   0     coefficient 24 = blinding shift of bidder 1
 *   mask        :  uniform, except 0 at every score position
 * ```
 */
export function encodeBid(setup: Setup, index: number, bid: number, rng: Rng): Encoded<RankSecret> {
  const { ring } = setup
  const blinding = rng.range(1, ring.t)
  const blindingTerm = ring.zeros()
  blindingTerm[blindingShift(setup, index)] = blinding
  const mask = uniformSlots(ring.degree, ring.t, rng)
  for (let other = 0; other < setup.bidders; other++) mask[scorePosition(setup, other)] = 0
  const placedBid = windowCenter(setup, index) + bid
  const plaintexts = [ring.monomial(placedBid), ring.monomial(-bid), blindingTerm, mask].map((c) => ring.toSlots(c))
  return { plaintexts, secret: { blinding } }
}

/** The server tally: 2 ct×ct products for all bidders. */
export function evaluate(setup: Setup, inputs: Ciphertext[][], evaluator: Evaluator): Ciphertext {
  const { ring } = setup
  const n = setup.bidders
  const sum = (part: number) => inputs.map((s) => s[part]).reduce((acc, ct) => acc.add(ct))
  // Σ_j X^-b_j · Σ_{k≥0} X^-k: coefficient 0 of X^d times this is [d ≥ 0].
  const atMost = evaluator.show('Σ_j X^-b_j · step', evaluator.mulPlain(sum(1), ring.toSlots(step(setup, 0))))
  // Coefficient s_i of this product is W_i = #{j : b_j ≤ b_i}.
  const wins = evaluator.show('Σ_i X^(s_i + b_i) · Σ_j X^-b_j · step', evaluator.mul(sum(0), atMost))
  const all = ring.zeros()
  for (let index = 0; index < n; index++) all[windowCenter(setup, index)] = n % ring.t
  // (W_i - n) at every window center, then one product with Σ_k ρ_k X^(3Bn·k) blinds each score.
  const scores = evaluator.show('(wins - n at each center) · Σ blinding', evaluator.mul(wins.subPlain(ring.toSlots(all)), sum(2)))
  return evaluator.show('output = scores + Σ masks', scores.add(sum(3)))
}

/** Reads the `n` score coefficients: on a tie for the highest bid, every tied bidder shows a zero. The highest index wins. */
export function decode(setup: Setup, outputSlots: Slots): PublicResult {
  const coefficients = setup.ring.toCoefficients(outputSlots)
  for (let index = setup.bidders - 1; index >= 0; index--) {
    if (coefficients[scorePosition(setup, index)] === 0) return { winner: index, price: null }
  }
  return { winner: null, price: null }
}

/** The competition rank of bidder `index`: `score = ρ · (W - n)`, so `W = score / ρ + n` and the rank is `n - W + 1`. */
export function ownRank(setup: Setup, outputSlots: Slots, index: number, secret: RankSecret): number | null {
  const { t } = setup.ring
  const n = setup.bidders
  const score = setup.ring.toCoefficients(outputSlots)[scorePosition(setup, index)]
  const atOrBelow = (((score * inverse(secret.blinding, t)) % t) + n) % t
  return atOrBelow >= 1 && atOrBelow <= n ? n - atOrBelow + 1 : null
}

/** Competition ranks: `1 + #{j : b_j > b_i}`. */
export function expectedRanks(bids: number[]): number[] {
  return bids.map((bid) => 1 + bids.filter((other) => other > bid).length)
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
    note: `coefficients, not slots. The center of window i is at offset 2B = ${2 * setup.levels}. The blinded score of bidder i is past the windows. Coefficient N-k holds the exponent -k.`,
  }
}

export const rankBatched: Design<RankSecret> = {
  name: 'rank-batched',
  disclosure: 'winner only, and a tie for the highest bid; each bidder can read its own rank (if 1 bidder mask is honest)',
  priceRule: 'none',
  readout: 'reads n score coefficients: a zero names a winner',
  inputNames: ['X^(s_i + b)', 'X^-b', 'blinding ρ_i · X^shift_i', 'mask'],
  randomTieOrder: false,
  revealsOwnRank: true,
  depth: () => 2,
  check(setup) {
    const n = setup.bidders
    checkCapacity(setup, n * n * window(setup), n)
  },
  encodeBid,
  evaluate,
  decode,
  layout,
  ownRank,
  expectedRanks,
}
