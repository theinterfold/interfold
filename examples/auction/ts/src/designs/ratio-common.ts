// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * Shared by `rl-first-price` and `rl-second-price`: the ratio-lane auctions. A ratio lane
 * carries a sum of bidder weights. The reader takes the winner set from the value of the lane, or
 * from a ratio of two lanes, and not from a zero pattern over one region for each bidder. Thus
 * the output needs only `⌈n / W⌉` lanes for each price level.
 *
 * **Weights.** `W = ⌊log2 t⌋`. Bidder `k` has the weight `w_k = 2^(k mod W)` in the weight group
 * `⌊k / W⌋`. A sum of the weights of some bidders in one group is below `2^W ≤ t`, and its bits
 * say which bidders. A group has `W` bidders at most. There are `g = ⌈n / W⌉` groups.
 *
 * **Slots.** The ring holds blocks of `B` slots, with the price level `p` at the offset `p` of a
 * block. A block is one lane for each price level. Each design says which blocks it has. The
 * slot after the last block is the random lane.
 *
 * **Random lane.** The random lane holds `m`, the sum of the bidder masks, at one slot that no
 * result lane uses. It is uniform if one bidder is honest, it is fixed only by the masks of all
 * bidders, and it is public with the result, so no bidder can predict it or grind for it. The
 * winner is `tieSet[random mod |tieSet|]`. With `|tieSet| = 1`, the winner is that bidder. The
 * bias of `random mod |tieSet|` is below `|tieSet| / t`. The output leaks the winner, the price,
 * the tie set (all its bids equal the price), and the random value: nothing else.
 *
 * Each bidder sends the thermometers `[b ≥ p]` and `[b > p]` copied into every block, and a
 * uniform mask. They do not depend on the bidder index: the program applies the weights with
 * plaintext selectors (ct×pt).
 */

import type { Ciphertext } from '../evaluator'
import type { Slots } from '../field'
import { uniformSlots, type Rng } from '../rng'
import type { Encoded, LaneKind, LaneReadout, LaneRow, Layout, PublicResult, Setup } from './design'

/** `W = ⌊log2 t⌋`: the bidders in one weight group. A sum of their weights is below `2^W ≤ t`. */
export function weightBits(t: number): number {
  return 31 - Math.clz32(t)
}

/** The number of weight groups `g = ⌈n / W⌉`. */
export function groupCount(setup: Setup): number {
  return Math.ceil(setup.bidders / weightBits(setup.ring.t))
}

/** The number of bidders in weight group `group`. The last group can be smaller than `W`. */
export function groupSize(setup: Setup, group: number): number {
  const width = weightBits(setup.ring.t)
  return Math.min(width, setup.bidders - group * width)
}

/** The name of a weight group in the trace, for example `bidders 0..12`. */
function groupName(setup: Setup, group: number): string {
  const first = group * weightBits(setup.ring.t)
  return `bidders ${first}..${first + groupSize(setup, group) - 1}`
}

/** The slot of the random lane: the slot after the last block. */
export function randomSlot(setup: Setup, blocks: number): number {
  return blocks * setup.levels
}

/**
 * The thermometers `[b ≥ p]` and `[b > p]` in every block. The slots after the last block, where
 * the random lane is, hold 0.
 *
 * ```text
 * B = 4 levels, 2 blocks, bid b = 2
 *
 *   slot     :  0 1 2 3 | 4 5 6 7
 *   level p  :  0 1 2 3 | 0 1 2 3
 *   [b >= p] :  1 1 1 0 | 1 1 1 0
 *   [b >  p] :  1 1 0 0 | 1 1 0 0
 * ```
 */
export function thermometers(setup: Setup, blocks: number, bid: number): [atLeast: Slots, above: Slots] {
  const atLeast = setup.ring.zeros()
  const above = setup.ring.zeros()
  for (let block = 0; block < blocks; block++) {
    const start = block * setup.levels
    atLeast.fill(1, start, start + bid + 1)
    above.fill(1, start, start + bid)
  }
  return [atLeast, above]
}

/** The bid plaintexts followed by a uniform mask, and by any further `masks`. */
export function withMasks(setup: Setup, plaintexts: Slots[], extra: Slots[], rng: Rng): Encoded {
  const mask = uniformSlots(setup.ring.degree, setup.ring.t, rng)
  return { plaintexts: [...plaintexts, mask, ...extra], secret: undefined }
}

/** `w_bidder` in the `B` slots of each block that starts at one of `starts`, and 0 elsewhere. */
export function weightSelector(setup: Setup, bidder: number, starts: number[]): Slots {
  const selector = setup.ring.zeros()
  const weight = 2 ** (bidder % weightBits(setup.ring.t))
  for (const start of starts) selector.fill(weight, start, start + setup.levels)
  return selector
}

/** `Σ cts`. */
export function sumAll(cts: Ciphertext[]): Ciphertext {
  return cts.reduce((acc, ct) => acc.add(ct))
}

/**
 * The bidders of a weight group that its value names: bit `i` of `value` is bidder
 * `group · W + i`. `null` when the value has a bit at or above the size of the group.
 */
function groupBidders(setup: Setup, group: number, value: number): number[] | null {
  const first = group * weightBits(setup.ring.t)
  const size = groupSize(setup, group)
  if (value >= 2 ** size) return null
  return Array.from({ length: size }, (_, i) => i)
    .filter((i) => Math.floor(value / 2 ** i) % 2 === 1)
    .map((i) => first + i)
}

/** The tie set that the group values name, ascending. `null` when a value is invalid or the set is empty. */
export function tieSetFrom(setup: Setup, groupValues: number[]): number[] | null {
  const tieSet: number[] = []
  for (let group = 0; group < groupValues.length; group++) {
    const bidders = groupBidders(setup, group, groupValues[group])
    if (bidders === null) return null
    tieSet.push(...bidders)
  }
  return tieSet.length === 0 ? null : tieSet
}

/** `tieSet[random mod |tieSet|]` for an ascending `tieSet`. */
export function pickWinner(tieSet: number[], random: number): number {
  return tieSet[random % tieSet.length]
}

/** What the rule gives on the plaintext bids: the price level, and the bidders whose bid is the price. */
export function plainTieSet(bids: number[], rule: 'first' | 'second'): { price: number; tieSet: number[] } {
  const sorted = [...bids].sort((a, b) => b - a)
  const price = rule === 'first' ? sorted[0] : sorted[1]
  // The set is the bidders with the highest bid: one bidder, or all that tie for it. At a tie
  // for the highest bid, the second price is that bid too.
  const tieSet = bids.flatMap((bid, i) => (bid === sorted[0] ? [i] : []))
  return { price, tieSet }
}

/**
 * The result that the program must output: the price rule and the tie set on the plaintext bids,
 * and the random value from the sum of the plaintext masks. `maskIndex` is the input of the mask.
 */
export function expectedLane(
  setup: Setup,
  bids: number[],
  inputs: Slots[][],
  rule: 'first' | 'second',
  maskIndex: number,
  slot: number,
): PublicResult {
  const { price, tieSet } = plainTieSet(bids, rule)
  const random = inputs.reduce((sum, bidder) => (sum + bidder[maskIndex][slot]) % setup.ring.t, 0)
  return { winner: pickWinner(tieSet, random), price, tieSet, random }
}

/** The kind of a lane value at `level`: 0, the result at the price level, or uniform below it. */
function laneKind(value: number, level: number, price: number | null): LaneKind {
  if (value === 0) return 'zero'
  return level === price ? 'result' : 'random'
}

/** A lane row from the `B` slots at `start`. */
export function laneRow(setup: Setup, name: string, slots: Slots, start: number, price: number | null): LaneRow {
  const values = slots.slice(start, start + setup.levels)
  return { name, values, kinds: values.map((value, level) => laneKind(value, level, price)) }
}

/**
 * Builds the readout from the lanes: the tie set from the group values, and the winner from the
 * random lane at `slot`. The tie set is empty when no lane is set, the copies disagree, or a
 * group value names a bidder that does not exist.
 */
export function readoutOf(
  setup: Setup,
  slots: Slots,
  slot: number,
  parts: { price: number | null; groupValues: number[]; copies: number; copy: number; copiesAgree: boolean; rows: LaneRow[] },
): LaneReadout {
  const tieSet = parts.price === null || !parts.copiesAgree ? null : tieSetFrom(setup, parts.groupValues)
  return {
    ...parts,
    tieSet: tieSet ?? [],
    groupSizes: parts.groupValues.map((_, group) => groupSize(setup, group)),
    random: slots[slot],
    winner: tieSet === null ? null : pickWinner(tieSet, slots[slot]),
  }
}

/** The regions of one copy and the random lane, for `--trace`. */
export function laneLayout(setup: Setup, names: string[], randomAt: number, note: string): Layout {
  return {
    domain: 'slots',
    regions: [
      ...names.map((name, block) => ({ name, start: block * setup.levels, length: setup.levels })),
      { name: 'random lane m', start: randomAt, length: 1 },
    ],
    note,
  }
}

/** The names of the weight groups, for the layout of a design. */
export function groupNames(setup: Setup, prefix: string): string[] {
  return Array.from({ length: groupCount(setup) }, (_, group) => `${prefix} ${group} (${groupName(setup, group)})`)
}
