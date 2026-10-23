// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * First-price with ratio lanes: 1 ct×ct product for any number of bidders, no error
 * probability. See `ratio-common.ts` for the weights, the slots, and the random lane.
 *
 * The ring holds one block of `B` slots for each weight group. With `Z_γ[p] = Σ_{k ∈ γ} w_k [b_k ≥ p]`,
 * `A[p] = #{k : b_k > p}`, and `m` the sum of the masks, slot `p` of block `γ` is
 *
 * ```text
 * out_γ[p] = Z_γ[p] + m[p] · A[p]
 * ```
 *
 * - `p > max`: `Z = 0` and `A = 0`, so the slot is 0.
 * - `p = max`: `A = 0`, so the slot is `Z_γ[max] = Σ w_k` over the tied bidders of group `γ`. The
 *   slot has no mask: the reader gets the tie set without error.
 * - `p < max`: `A ≥ 1`, so `m · A` is uniform and the slot is uniform.
 *
 * The slot after the last block holds `m`: the random lane that picks the winner from the tie set.
 */

import type { Ciphertext, Evaluator } from '../evaluator'
import type { Slots } from '../field'
import type { Rng } from '../rng'
import { checkCapacity, type Design, type Encoded, type LaneReadout, type Layout, type PublicResult, type Setup } from './design'
import {
  expectedLane,
  groupCount,
  groupNames,
  laneLayout,
  laneRow,
  randomSlot,
  readoutOf,
  sumAll,
  thermometers,
  weightBits,
  weightSelector,
  withMasks,
} from './ratio-common'

/**
 * The 3 plaintexts of one bidder: `[b ≥ p]` and `[b > p]` in every block, and the mask. The
 * index is not used: the program applies the weights.
 *
 * ```text
 * 2 weight groups, B = 4 levels, bid b = 2. The random lane is slot 8.
 *
 *   slot     :  0 1 2 3 | 4 5 6 7 | 8
 *   level p  :  0 1 2 3 | 0 1 2 3 |
 *   [b >= p] :  1 1 1 0 | 1 1 1 0 | 0
 *   [b >  p] :  1 1 0 0 | 1 1 0 0 | 0
 *   mask     :  uniform random value in every slot
 * ```
 */
export function encodeBid(setup: Setup, _index: number, bid: number, rng: Rng): Encoded {
  return withMasks(setup, thermometers(setup, groupCount(setup), bid), [], rng)
}

/**
 * The server tally: `Z + m · (A + [random slot])`. One ct×ct product at depth 1, and one ct×pt
 * product for each bidder (its weight).
 */
export function evaluate(setup: Setup, inputs: Ciphertext[][], evaluator: Evaluator): Ciphertext {
  const groups = groupCount(setup)
  const weighted = inputs.map((bidder, k) => {
    const group = Math.floor(k / weightBits(setup.ring.t))
    return evaluator.mulPlain(bidder[0], weightSelector(setup, k, [group * setup.levels]))
  })
  const atLeast = evaluator.show('Z = Σ w_k [b_k >= p], in the block of its group', sumAll(weighted))
  const above = evaluator.show('A = #{k : b_k > p}', sumAll(inputs.map((s) => s[1])))
  const masks = evaluator.show('m = Σ masks', sumAll(inputs.map((s) => s[2])))
  // A is 0 outside the blocks. The unit in the random slot gives m there.
  const unit = setup.ring.onesIn([[randomSlot(setup, groups), randomSlot(setup, groups) + 1]])
  const blind = evaluator.show('m · (A + [random slot])', evaluator.mul(masks, above.addPlain(unit)))
  return evaluator.show('output = Z + m · (A + [random slot])', atLeast.add(blind))
}

/**
 * Reads the lanes. The price is the highest level where a block is non-zero. The value of block
 * `γ` at that level names the tied bidders of group `γ`.
 */
export function readLanes(setup: Setup, outputSlots: Slots): LaneReadout {
  const groups = groupCount(setup)
  const levels = setup.levels
  let price: number | null = null
  for (let level = levels - 1; level >= 0 && price === null; level--) {
    if (Array.from({ length: groups }, (_, group) => outputSlots[group * levels + level]).some((value) => value !== 0)) price = level
  }
  const groupValues = Array.from({ length: groups }, (_, group) => (price === null ? 0 : outputSlots[group * levels + price]))
  const names = groupNames(setup, 'group')
  const rows = names.map((name, group) => laneRow(setup, name, outputSlots, group * levels, price))
  return readoutOf(setup, outputSlots, randomSlot(setup, groups), { price, groupValues, copies: 1, copy: 0, copiesAgree: true, rows })
}

export function decode(setup: Setup, outputSlots: Slots): PublicResult {
  const { winner, price, tieSet, random } = readLanes(setup, outputSlots)
  return { winner, price, tieSet, random }
}

function layout(setup: Setup): Layout {
  return laneLayout(
    setup,
    groupNames(setup, 'group'),
    randomSlot(setup, groupCount(setup)),
    'One block for each weight group, one slot for each level. At the price level a block holds the weights of its tied bidders; below it the block is uniform; above it the block is 0.',
  )
}

export const rlFirstPrice: Design = {
  name: 'rl-first-price',
  disclosure: 'winning bid, the bidders that tie for it, and a random value that picks the winner among them',
  priceRule: 'first',
  readout: 'price = the highest non-zero level; tie set = the bits of each group value at that level; winner = tie set[random mod size]',
  inputNames: ['[b >= p]', '[b > p]', 'mask'],
  randomTieOrder: false,
  randomLane: true,
  revealsOwnRank: false,
  depth: () => 1,
  check(setup) {
    // A ≤ n must be non-zero mod t when A ≥ 1: the slots below the price are uniform. This is n < t.
    checkCapacity(setup, randomSlot(setup, groupCount(setup)) + 1, setup.bidders + 1)
  },
  encodeBid,
  evaluate,
  decode,
  expected: (setup, bids, inputs) => expectedLane(setup, bids, inputs, 'first', 2, randomSlot(setup, groupCount(setup))),
  readLanes,
  layout,
}
