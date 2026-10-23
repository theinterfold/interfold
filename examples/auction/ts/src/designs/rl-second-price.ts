// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * Second-price with ratio lanes: 6 ct×ct products at depth 3 for any number of bidders. See
 * `ratio-common.ts` for the weights, the slots, and the random lane.
 *
 * One copy holds `1 + g` blocks of `B` slots: the lane `y` and one lane `z_γ` for each weight
 * group `γ`. The ring holds as many copies as fit. With `C[p] = #{k : b_k ≥ p}`, `A[p] = #{k : b_k > p}`,
 * `G_γ`, `E_γ` the weighted sums of `[b > p]` and `[b = p]` over group `γ`, `m` the sum of the
 * masks, and `R` the sum of the pair masks:
 *
 * ```text
 * c   = C · (C - 1)         u   = A · (A - 1)         L_γ = G_γ + (1 - A) · E_γ
 * y   = R · c               + m_y  · u
 * z_γ = R · c · L_γ         + m_zγ · u
 * ```
 *
 * With `s` the second-highest bid (the highest bid at a tie for it):
 *
 * - `p > s`: `C ≤ 1` and `A ≤ 1`, so `c = u = 0`: both lanes are 0.
 * - `p = s`: `u = 0`. The lanes are `(R · c, R · c · L_γ)`. The ratio `z_γ / y = L_γ` is the sum of
 *   the weights of group `γ` in the winner set: the unique winner at `s`, or the tie set at a tie
 *   for the highest bid. `c ≠ 0` because `n (n - 1) < t`.
 * - `p < s`: `A ≥ 2`, so `u ≠ 0`. Each lane is uniform, and the lanes are independent.
 *
 * `R` is the same in `y` and in every `z_γ` of one level of one copy: a bidder sends a pair mask
 * with this shape, and a proof of the shape is part of its submission. Without the shape, the
 * ratio would not be `L_γ`. A level reads as 0 by error when `R = 0` at the price, with probability
 * `1/t` for each copy. The reader takes the highest price over the copies, so the error is
 * `t^-copies`.
 */

import type { Ciphertext, Evaluator } from '../evaluator'
import { inverse, type Slots } from '../field'
import { uniformSlots, type Rng } from '../rng'
import {
  checkCapacity,
  type Design,
  type Encoded,
  type LaneReadout,
  type LaneRow,
  type Layout,
  type PublicResult,
  type Setup,
} from './design'
import {
  expectedLane,
  groupCount,
  groupNames,
  laneLayout,
  laneRow,
  readoutOf,
  sumAll,
  thermometers,
  weightBits,
  weightSelector,
  withMasks,
} from './ratio-common'

/** The blocks of one copy: `y` and one `z_γ` for each weight group. */
function blocksPerCopy(setup: Setup): number {
  return 1 + groupCount(setup)
}

/** The copies that fit the ring, with one slot kept for the random lane. */
export function copies(setup: Setup): number {
  return Math.floor((setup.ring.degree - 1) / (blocksPerCopy(setup) * setup.levels))
}

/** The slot of the random lane: after the last copy. */
function randomAt(setup: Setup): number {
  return copies(setup) * blocksPerCopy(setup) * setup.levels
}

/** The first slot of block `block` (0 = `y`, `1 + γ` = `z_γ`) in `copy`. */
function blockStart(setup: Setup, copy: number, block: number): number {
  return (copy * blocksPerCopy(setup) + block) * setup.levels
}

/** The 4 slot vectors of one bidder, except the mask: `[b ≥ p]`, `[b > p]`, and the pair mask. */
export function encodeBid(setup: Setup, _index: number, bid: number, rng: Rng): Encoded {
  const blocks = copies(setup) * blocksPerCopy(setup)
  // The pair mask: one uniform value for each (copy, level), the same in every block of the copy.
  //
  //   copy 0:  y         z_0       z_1      ...
  //   slots :  v0 v1 v2 | v0 v1 v2 | v0 v1 v2 | ...      (B = 3, R = Σ pair masks)
  const pairMask = setup.ring.zeros()
  for (let copy = 0; copy < copies(setup); copy++) {
    const values = uniformSlots(setup.levels, setup.ring.t, rng)
    for (let block = 0; block < blocksPerCopy(setup); block++) {
      values.forEach((value, level) => (pairMask[blockStart(setup, copy, block) + level] = value))
    }
  }
  return withMasks(setup, thermometers(setup, blocks, bid), [pairMask], rng)
}

/**
 * The server tally, 6 ct×ct at depth 3 and 2 ct×pt for each bidder (its weight in `G` and in `Z`):
 * `(R · c) · L' + m · (u + [random slot])`, with `L' = L + [y blocks]`.
 */
export function evaluate(setup: Setup, inputs: Ciphertext[][], evaluator: Evaluator): Ciphertext {
  const ring = setup.ring
  const copyCount = copies(setup)
  const allCopies = Array.from({ length: copyCount }, (_, copy) => copy)

  // Bidder k puts its weight in the `z` block of its group, in every copy.
  const weightsOf = (k: number) =>
    weightSelector(
      setup,
      k,
      allCopies.map((copy) => blockStart(setup, copy, 1 + Math.floor(k / weightBits(ring.t)))),
    )
  const weightedAbove = evaluator.show(
    'G = Σ w_k [b_k > p], in the z block of its group',
    sumAll(inputs.map((s, k) => evaluator.mulPlain(s[1], weightsOf(k)))),
  )
  const weightedAtLeast = sumAll(inputs.map((s, k) => evaluator.mulPlain(s[0], weightsOf(k))))
  const weightedEqual = evaluator.show('E = Σ w_k [b_k = p] = Z - G', weightedAtLeast.sub(weightedAbove))

  const atLeast = evaluator.show('C = #{k : b_k >= p}', sumAll(inputs.map((s) => s[0])))
  const above = evaluator.show('A = #{k : b_k > p}', sumAll(inputs.map((s) => s[1])))
  const masks = evaluator.show('m = Σ masks', sumAll(inputs.map((s) => s[2])))
  const pairMasks = evaluator.show('R = Σ pair masks', sumAll(inputs.map((s) => s[3])))
  const one = ring.constant(1)

  const twoAtLeast = evaluator.show('c = C (C - 1)', evaluator.mul(atLeast, atLeast.subPlain(one)))
  const twoAbove = evaluator.show('u = A (A - 1)', evaluator.mul(above, above.subPlain(one)))
  // L = G + (1 - A) · E is in the z blocks. L' is also 1 in the y blocks.
  const ratioIn = evaluator.show('L = G + (1 - A) · E', weightedAbove.add(evaluator.mul(weightedEqual, above.neg().addPlain(one))))
  const yBlocks = ring.onesIn(allCopies.map((copy): [number, number] => [blockStart(setup, copy, 0), blockStart(setup, copy, 1)]))
  const ratioLanes = ratioIn.addPlain(yBlocks)
  const blinded = evaluator.show('R · c', evaluator.mul(pairMasks, twoAtLeast))
  const signal = evaluator.show("R · c · L'", evaluator.mul(blinded, ratioLanes))
  // u is 0 outside the blocks. The unit in the random slot gives m there.
  const unit = ring.onesIn([[randomAt(setup), randomAt(setup) + 1]])
  const noise = evaluator.show('m · (u + [random slot])', evaluator.mul(masks, twoAbove.addPlain(unit)))
  return evaluator.show("output = R · c · L' + m · (u + [random slot])", signal.add(noise))
}

/**
 * Reads the lanes. In each copy, the price is the highest level where `y` is non-zero. The price
 * of the output is the highest over the copies. At the price, `z_γ / y` of a copy where `y` is
 * non-zero gives the weights of group `γ` in the winner set. All such copies must agree.
 */
export function readLanes(setup: Setup, outputSlots: Slots): LaneReadout {
  const { levels } = setup
  const { t } = setup.ring
  const groups = groupCount(setup)
  const copyCount = copies(setup)
  const lanePrice = (copy: number): number | null => {
    for (let level = levels - 1; level >= 0; level--) {
      if (outputSlots[blockStart(setup, copy, 0) + level] !== 0) return level
    }
    return null
  }
  const prices = Array.from({ length: copyCount }, (_, copy) => lanePrice(copy))
  const price = prices.reduce<number | null>((best, p) => (p !== null && (best === null || p > best) ? p : best), null)
  // The copies that fixed the price: their `y` is non-zero there.
  const fixing = price === null ? [] : prices.flatMap((p, copy) => (p === price ? [copy] : []))
  const ratios = fixing.map((copy) => {
    const y = outputSlots[blockStart(setup, copy, 0) + (price as number)]
    return Array.from(
      { length: groups },
      (_, group) => (outputSlots[blockStart(setup, copy, 1 + group) + (price as number)] * inverse(y, t)) % t,
    )
  })
  const copiesAgree = ratios.every((row) => row.every((value, group) => value === ratios[0][group]))
  const shown = fixing[0] ?? 0
  const rows: LaneRow[] = ['y', ...groupNames(setup, 'z')].map((name, block) =>
    laneRow(setup, name, outputSlots, blockStart(setup, shown, block), price),
  )
  return readoutOf(setup, outputSlots, randomAt(setup), {
    price,
    groupValues: ratios[0] ?? new Array<number>(groups).fill(0),
    copies: copyCount,
    copy: shown,
    copiesAgree,
    rows,
  })
}

export function decode(setup: Setup, outputSlots: Slots): PublicResult {
  const { winner, price, tieSet, random } = readLanes(setup, outputSlots)
  return { winner, price, tieSet, random }
}

function layout(setup: Setup): Layout {
  return laneLayout(
    setup,
    ['y', ...groupNames(setup, 'z')],
    randomAt(setup),
    `Copy 0 of ${copies(setup)} copies: the lane y, then one lane z for each weight group. At the price level z / y is the weight sum of the winner set in that group; below it both are uniform; above it both are 0.`,
  )
}

export const rlSecondPrice: Design = {
  name: 'rl-second-price',
  disclosure: 'second-highest bid, the winner set, and a random value that picks the winner in it (if 1 bidder mask is honest)',
  priceRule: 'second',
  readout: 'price = the highest level with y ≠ 0; winner set = the bits of z / y at that level; winner = set[random mod size]',
  inputNames: ['[b >= p]', '[b > p]', 'mask', 'mask R (the same in the y and z lanes)'],
  randomTieOrder: false,
  randomLane: true,
  revealsOwnRank: false,
  depth: () => 3,
  check(setup) {
    // c = C (C - 1) and u = A (A - 1) must be non-zero mod t when C, A ≥ 2: n (n - 1) < t.
    checkCapacity(setup, blocksPerCopy(setup) * setup.levels + 1, setup.bidders * (setup.bidders - 1) + 1)
  },
  encodeBid,
  evaluate,
  decode,
  expected: (setup, bids, inputs) => expectedLane(setup, bids, inputs, 'second', 2, randomAt(setup)),
  readLanes,
  layout,
}
