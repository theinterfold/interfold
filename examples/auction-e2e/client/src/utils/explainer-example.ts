// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * The worked example of the explainers of the zero-failure types: 3 bidders with the bids 2, 3 and
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
