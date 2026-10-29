// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * The worked example of the two second-price explainers: 3 bidders with the bids 2, 3 and
 * 1. For each level `l` the table holds the number `C` of bidders that bid at least `l`, the factor
 * `C × (C − 1)`, how many rivals beat each bidder at `l` (`beaten`), and `tests = beaten × C × (C − 1)`.
 * Bidder 1 wins at level 2.
 */
const EXAMPLE = {
  bids: [2, 3, 1],
  levels: [
    { level: 0, atLeast: 3, beaten: [2, 2, 2] },
    { level: 1, atLeast: 3, beaten: [1, 1, 2] },
    { level: 2, atLeast: 2, beaten: [1, 0, 2] },
    { level: 3, atLeast: 1, beaten: [1, 0, 1] },
  ],
} as const

/** The cells of one level of the example table. */
export function exampleRows() {
  return EXAMPLE.levels.map(({ level, atLeast, beaten }) => {
    const factor = atLeast * (atLeast - 1)
    const tests = beaten.map((count) => count * factor)
    return { level, atLeast, factor, beaten, tests }
  })
}

/** The worked example of the first-price explainer: 3 bidders, and a tie at the top bid. */
export const FIRST_PRICE_BIDS = [2, 3, 3] as const

/** What one slot of a lane holds after the program: `zero`, exactly `one`, or a number that looks `random`. */
export type LaneSlot = 'zero' | 'one' | 'random'

/**
 * The slots of the first-price example, level by level, computed with the formula of the program:
 * `out = ge + mask × A`, where `A` is the number of bidders with a bid above the level plus the earlier
 * bidders with a bid exactly at the level. A slot with `A = 0` is `ge`, 0 or 1. A slot with `A ≥ 1`
 * holds a number that the mask makes random.
 */
export function firstPriceRows(levels: number) {
  const bids = FIRST_PRICE_BIDS
  return Array.from({ length: levels }, (_, level) => {
    const above = bids.filter((bid) => bid > level).length
    const lanes = bids.map((bid, lane) => {
      const earlierAtLevel = bids.slice(0, lane).filter((other) => other === level).length
      const rivals = above + earlierAtLevel
      const ge = bid >= level
      const slot: LaneSlot = rivals > 0 ? 'random' : ge ? 'one' : 'zero'
      return { ge, rivals, slot }
    })
    return { level, lanes }
  })
}
