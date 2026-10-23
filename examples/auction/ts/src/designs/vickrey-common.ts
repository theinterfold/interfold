// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * Shared by `vickrey` and `vickrey-compact`: second-price auction with 4 ct×ct products for any
 * number of bidders. The output shows the winner and the second-highest bid only.
 *
 * The slots hold one region of `B` slots for each candidate winner. Region `k` belongs to the
 * bidder with tie priority `k` (`Setup.tiePriority`); below, `b_k` is the bid of that bidder.
 * Slot `p` of region `k` tests whether that bidder beats every other bidder at level `p`:
 *
 * ```text
 * g_k[p] = #{j ≠ k : b_j > p} + [b_k < p] + [b_k = p] · #{j > k : b_j = p}
 * ```
 *
 * `g_k[p] = 0` exactly when no other bid is above `p`, `b_k ≥ p`, and no higher priority ties
 * `k` at `p`. The program outputs `g · c'(c' - 1) · r`, where `c'[p] = #{j : b_j ≥ p}` and `r`
 * is the sum of the bidder masks. With `s` the second-highest bid:
 *
 * - `p < s`: two or more bids are above `p`, so `g ≥ 1` and `c' ≥ 2`. The slot is uniform.
 * - `p = s`: `c' ≥ 2`, and `g = 0` only in the region of the winner (ties go to the higher
 *   priority). The slot is 0 for the winner and uniform for all other regions.
 * - `p > s`: one bid or none is at or above `p`, so `c'(c' - 1) = 0`. The slot is 0.
 *
 * Thus the output is a function of the winner and `s` only, plus uniform values. It does not
 * show the winning bid, the runner-up, any count, or a tie.
 *
 * Each bidder sends ciphertexts that do not depend on its index: the thermometers `[b ≥ p]` and
 * `[b > p]`, copied into every region, and a mask. Their difference is the one-hot `[b = p]`.
 * The program places the own-region and tie-break terms with plaintext selectors (ct×pt). Thus
 * the tie priority can be drawn at random after the bids close, at no cost, and a tie goes to a
 * random tied bidder.
 *
 * Spare slots hold copies of the regions under independent mask values. A slot reads as zero
 * by error only when it is zero in every copy, with probability `t^-copies`.
 */

import type { Ciphertext, Evaluator } from '../evaluator'
import type { Range, Slots } from '../field'
import { uniformSlots, type Rng } from '../rng'
import { checkCapacity, type Encoded, type Layout, type PublicResult, type Setup } from './design'

/** The slots of one copy: one region of `B` slots for each bidder. */
export function copySize(setup: Setup): number {
  return setup.bidders * setup.levels
}

/** The number of copies of the regions that fit the ring. */
export function copies(setup: Setup): number {
  return Math.floor(setup.ring.degree / copySize(setup))
}

/** The slot of `level` in `region` of `copy`. */
export function slot(setup: Setup, copy: number, region: number, level: number): number {
  return copy * copySize(setup) + region * setup.levels + level
}

/**
 * The level of SIMD slot `index`, or `null` for a slot beyond the last copy. Every region of
 * every copy holds the same bid plaintext, so a bid proof needs only this map from slots to
 * levels.
 */
export function slotLevel(setup: Setup, index: number): number | null {
  return index < copies(setup) * copySize(setup) ? index % setup.levels : null
}

/** Whether slot `level` of `region` is non-zero in one or more copies. */
function isSet(setup: Setup, slots: Slots, region: number, level: number): boolean {
  for (let copy = 0; copy < copies(setup); copy++) {
    if (slots[slot(setup, copy, region, level)] !== 0) return true
  }
  return false
}

/**
 * The thermometers `[b ≥ p]` and `[b > p]` in every region of every copy.
 *
 * ```text
 * n = 2 bidders, B = 4 levels, bid b = 2. One copy is n·B = 8 slots: region 0, then region 1.
 * The ring holds N / 8 copies, and each copy repeats this pattern.
 *
 *   slot     :  0 1 2 3 | 4 5 6 7
 *   level p  :  0 1 2 3 | 0 1 2 3
 *   [b >= p] :  1 1 1 0 | 1 1 1 0
 *   [b >  p] :  1 1 0 0 | 1 1 0 0
 * ```
 */
export function thermometers(setup: Setup, bid: number): [atLeast: Slots, above: Slots] {
  const atLeast = setup.ring.zeros()
  const above = setup.ring.zeros()
  for (let copy = 0; copy < copies(setup); copy++) {
    for (let region = 0; region < setup.bidders; region++) {
      const start = slot(setup, copy, region, 0)
      atLeast.fill(1, start, start + bid + 1)
      above.fill(1, start, start + bid)
    }
  }
  return [atLeast, above]
}

/**
 * The slots of the one bid ciphertext of `vickrey-compact`: `[b ≥ p] + [b = p]`, which is
 * `2 · [b ≥ p] - [b > p]`. The value is 1 below the bid, 2 at the bid, and 0 above.
 *
 * ```text
 * n = 2 bidders, B = 4 levels, bid b = 2:
 *
 *   slot     :  0 1 2 3 | 4 5 6 7
 *   level p  :  0 1 2 3 | 0 1 2 3
 *   v        :  1 1 2 0 | 1 1 2 0
 * ```
 */
export function compactSlots(setup: Setup, bid: number): Slots {
  const [atLeast, above] = thermometers(setup, bid)
  return atLeast.map((ge, k) => 2 * ge - above[k])
}

/** The bid plaintexts followed by a uniform mask. */
export function withMask(setup: Setup, plaintexts: Slots[], rng: Rng): Encoded {
  const mask = uniformSlots(setup.ring.degree, setup.ring.t, rng)
  return { plaintexts: [...plaintexts, mask], secret: undefined }
}

export function sumAll(cts: Ciphertext[]): Ciphertext {
  return cts.reduce((acc, ct) => acc.add(ct))
}

/** Shared capacity check: `g ≤ 2n - 1` and `c' ≤ n` must be non-zero mod t when they are non-zero. */
export function check(setup: Setup): void {
  checkCapacity(setup, copySize(setup), 2 * setup.bidders)
}

/**
 * The program after the bids are thermometers: `g · c'(c' - 1) · r`, 4 ct×ct at depth 3 above
 * the depth of the inputs. `bids[j]` is `([b_j ≥ p], [b_j > p])`.
 */
export function testsUnderMask(
  setup: Setup,
  bids: [atLeast: Ciphertext, above: Ciphertext][],
  masks: Ciphertext,
  evaluator: Evaluator,
): Ciphertext {
  const ring = setup.ring
  const allCopies = Array.from({ length: copies(setup) }, (_, c) => c)
  // Region r: its own slots, and the slots of the regions below it (r wins a tie there).
  const own = (r: number) => ring.onesIn(allCopies.map((c): Range => [slot(setup, c, r, 0), slot(setup, c, r + 1, 0)]))
  const lower = (r: number) => ring.onesIn(allCopies.map((c): Range => [slot(setup, c, 0, 0), slot(setup, c, r, 0)]))

  // For each bidder j, with region k = its tie priority: the bid in region k only (own slots),
  // and [b_j = p] in the regions below k (the tie-break terms).
  const ownAtLeast: Ciphertext[] = []
  const ownAbove: Ciphertext[] = []
  const tiesAbove: Ciphertext[] = []
  bids.forEach(([atLeast, above], j) => {
    const region = setup.tiePriority[j]
    const selector = own(region)
    ownAtLeast.push(evaluator.mulPlain(atLeast, selector))
    ownAbove.push(evaluator.mulPlain(above, selector))
    tiesAbove.push(evaluator.mulPlain(atLeast.sub(above), lower(region)))
  })
  const ownAtLeastSum = evaluator.show('[b_k >= p] in region k', sumAll(ownAtLeast))
  const ownAboveSum = evaluator.show('[b_k > p] in region k', sumAll(ownAbove))
  const atLeastSum = evaluator.show("c' = #{j : b_j >= p}", sumAll(bids.map((b) => b[0])))
  const aboveSum = evaluator.show('#{j : b_j > p}', sumAll(bids.map((b) => b[1])))

  const one = ring.constant(1)
  // [b_k = p] · #{j > k : b_j = p} in region k.
  const ties = evaluator.show('ties = [b_k = p] · #{j > k : b_j = p}', evaluator.mul(ownAtLeastSum.sub(ownAboveSum), sumAll(tiesAbove)))
  // #{j ≠ k : b_j > p} + [b_k < p] + ties.
  const othersAbove = aboveSum.sub(ownAboveSum)
  const beaten = evaluator.show('g = #{j ≠ k : b_j > p} + [b_k < p] + ties', othersAbove.addPlain(one).sub(ownAtLeastSum).add(ties))
  const twoAtLeast = evaluator.show("c'(c' - 1)", evaluator.mul(atLeastSum, atLeastSum.subPlain(one)))
  const tests = evaluator.show("g · c'(c' - 1)", evaluator.mul(beaten, twoAtLeast))
  return evaluator.show("output = g · c'(c' - 1) · r", evaluator.mul(tests, masks))
}

/**
 * Reads the zero pattern. Loser regions are non-zero on `0..=s`, the winner region on `0..s`.
 * The price `s` is the last level that any region has set. The winner is the only region that
 * is clear at `s`.
 */
export function decodePattern(setup: Setup, outputSlots: Slots): PublicResult {
  const n = setup.bidders
  const levels = setup.levels
  const last = (region: number): number | null => {
    for (let level = levels - 1; level >= 0; level--) {
      if (isSet(setup, outputSlots, region, level)) return level
    }
    return null
  }
  const lasts = Array.from({ length: n }, (_, region) => last(region)).filter((x): x is number => x !== null)
  // Only when every loser slot `s` reads as zero by error.
  if (lasts.length === 0) return { winner: null, price: null }
  const price = Math.max(...lasts)
  const winners = Array.from({ length: n }, (_, region) => region).filter((region) => !isSet(setup, outputSlots, region, price))
  const bidder = (region: number) => setup.tiePriority.indexOf(region)
  return { winner: winners.length === 1 ? bidder(winners[0]) : null, price }
}

/**
 * The check that a contract runs on a claimed result, with 1 to `2 · copies + 1` slot
 * evaluations of N multiplications mod t each:
 *
 * 1. Slot `s` of the winner region is zero.
 * 2. Slot `s - 1` of the winner region is non-zero (when `s > 0`).
 * 3. Slot `s` of one other region is non-zero.
 *
 * Check 2 refuses a lower price, and check 3 refuses a loser that claims price `s + 1`.
 */
export function verifyClaim(setup: Setup, coefficients: number[], claim: PublicResult): boolean {
  if (claim.winner === null || claim.price === null) return false
  const n = setup.bidders
  const price = claim.price
  if (claim.winner >= n || price >= setup.levels) return false
  const ring = setup.ring
  const region = setup.tiePriority[claim.winner]
  const points = ring.slotPoints()
  const at = (copy: number, r: number, level: number) => ring.evaluate(coefficients, points[slot(setup, copy, r, level)])
  const set = (r: number, level: number) =>
    Array.from({ length: copies(setup) }, (_, copy) => copy).some((copy) => at(copy, r, level) !== 0)
  return at(0, region, price) === 0 && (price === 0 || set(region, price - 1)) && set((region + 1) % n, price)
}

/** The regions of copy 0, for `--trace`. Region `k` belongs to the bidder with priority `k`. */
export function vickreyLayout(setup: Setup): Layout {
  return {
    domain: 'slots',
    regions: Array.from({ length: setup.bidders }, (_, k) => ({
      name: `region ${k} (bidder ${setup.tiePriority.indexOf(k)})`,
      start: k * setup.levels,
      length: setup.levels,
    })),
    note: `copy 0 of ${copies(setup)} copies. Every copy has the same layout (the masks differ). Columns are levels p = 0..${setup.levels - 1}.`,
  }
}
