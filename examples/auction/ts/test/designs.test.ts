// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * Port of `tests/designs.rs`. Each test runs the plaintext simulation and compares what the
 * design reveals with the plain rule. A wrong slot layout or a wrong tally step changes the
 * result or the zero pattern, and the test fails.
 */

import { describe, expect, it } from 'vitest'
import {
  designs,
  firstPrice,
  firstPriceBlind,
  isCorrect,
  rank,
  rankBatched,
  run,
  secondPrice,
  secondPriceBlind,
  seededRng,
  SetupError,
  vickrey,
  vickreyCompact,
  type AnyDesign,
  type PublicResult,
  type RunResult,
} from '../src'
import { verify as verifyFirstPriceBlind } from '../src/designs/first-price-blind'
import { verify as verifySecondPriceBlind, winningBid } from '../src/designs/second-price-blind'
import { verify as verifyVickrey } from '../src/designs/vickrey'
import { copies } from '../src/designs/vickrey-common'

const LEVELS = 16

/** Bid sets that exercise ties, the range ends, and 2 to 8 bidders. */
const BID_SETS: number[][] = [
  [7, 3, 9, 9],
  [9, 9, 3, 7],
  [5, 5, 5, 5, 5],
  [0, 15],
  [15, 0],
  [0, 0],
  [1, 14, 2, 13, 3, 12, 4, 11],
]

/** Runs `design` on every bid set with at most `maxBidders` bidders. */
function assertCorrect(design: AnyDesign, maxBidders = Infinity): void {
  const rng = seededRng(1)
  for (const bids of BID_SETS.filter((set) => set.length <= maxBidders)) {
    const result = run(design, 'toy', bids, LEVELS, undefined, rng)
    expect(
      isCorrect(result),
      `${design.name} on ${bids}: public ${JSON.stringify(result.result)}, expected ${JSON.stringify(result.expected)}, own ranks ${result.ownRanks}, expected ${result.expectedRanks}`,
    ).toBe(true)
  }
}

describe('each design reveals what its rule says', () => {
  it('rank names the winner and each bidder reads its own rank', () => {
    assertCorrect(rank)
  })

  // Ties for the highest bid give several zeros; ranks are competition ranks.
  it('rank-batched names the winner and each bidder reads its own rank', () => {
    // 3 · n² · B must fit the 1024 toy coefficients: 4 bidders at 16 levels.
    assertCorrect(rankBatched, 4)
  })

  it('first-price reveals the winner and the winning bid', () => {
    assertCorrect(firstPrice)
  })

  it('first-price-blind reveals the winner and the winning bid', () => {
    assertCorrect(firstPriceBlind)
  })

  it('second-price reveals the winner and the second-highest bid', () => {
    assertCorrect(secondPrice)
  })

  it('second-price-blind reveals the winner and the second-highest bid', () => {
    assertCorrect(secondPriceBlind)
  })

  it('vickrey reveals the winner and the second-highest bid', () => {
    assertCorrect(vickrey)
  })

  it('vickrey-compact reveals the winner and the second-highest bid', () => {
    assertCorrect(vickreyCompact)
  })

  // The sets above are few. Random sets cover more shapes of ties and orders.
  it('every design is correct on random bid sets with many ties', () => {
    const rng = seededRng(11)
    for (let trial = 0; trial < 40; trial++) {
      const bidders = 2 + rng.range(0, 4)
      // 4 levels make ties likely.
      const bids = Array.from({ length: bidders }, () => rng.range(0, 4))
      for (const design of Object.values(designs)) {
        const result = run(design, 'toy', bids, 4, undefined, rng)
        expect(isCorrect(result), `${design.name} on ${bids}`).toBe(true)
      }
    }
  })

  it('the winner of a first-price tie is the higher index, and the second price counts the tie', () => {
    const first = run(firstPrice, 'toy', [4, 12, 9, 12], LEVELS)
    expect(first.result).toEqual({ winner: 3, price: 12 })
    const second = run(secondPrice, 'toy', [4, 12, 9, 12], LEVELS)
    expect(second.result).toEqual({ winner: 3, price: 12 })
  })
})

const claim = (winner: number, price: number): PublicResult => ({ winner, price })

// A contract checks a claimed result by evaluating the plaintext at slot points. The check
// must accept the true result and refuse a neighbouring winner or price.
describe('claim checks', () => {
  it('first-price-blind accepts only the true result', () => {
    const first = run(firstPriceBlind, 'toy', [4, 12, 9, 12], LEVELS, undefined, seededRng(4))
    const verify = (c: PublicResult) => verifyFirstPriceBlind(first.setup, first.outputCoefficients, c)
    expect(verify(claim(3, 12))).toBe(true)
    expect(verify(claim(1, 12)), 'the tie goes to the higher index').toBe(false)
    expect(verify(claim(3, 11))).toBe(false)
    expect(verify(claim(3, 13))).toBe(false)
  })

  it('second-price-blind accepts only the true result', () => {
    const second = run(secondPriceBlind, 'toy', [4, 12, 9, 2], LEVELS, undefined, seededRng(4))
    expect(winningBid(second.setup, second.outputSlots)).toBe(12)
    const verify = (c: PublicResult, top: number) => verifySecondPriceBlind(second.setup, second.outputCoefficients, c, top)
    expect(verify(claim(1, 9), 12)).toBe(true)
    expect(verify(claim(1, 8), 12)).toBe(false)
    expect(verify(claim(1, 10), 12)).toBe(false)
    expect(verify(claim(1, 9), 11)).toBe(false)
    expect(verify(claim(2, 9), 12)).toBe(false)
  })

  // The check must accept the true result and refuse a loser, a neighbouring price, and a
  // loser that claims one level more.
  it('vickrey accepts only the true result', () => {
    const report = run(vickrey, 'toy', [4, 12, 9, 2], LEVELS, undefined, seededRng(6))
    const verify = (winner: number, price: number) => verifyVickrey(report.setup, report.outputCoefficients, claim(winner, price))
    expect(verify(1, 9)).toBe(true)
    for (const [winner, price] of [
      [2, 9],
      [0, 9],
      [1, 8],
      [1, 10],
      [2, 10],
      [0, 10],
      [1, 0],
    ]) {
      expect(verify(winner, price), `claim (${winner}, ${price})`).toBe(false)
    }
  })
})

/**
 * Which (bidder, level) slots are non-zero in one or more copies of the vickrey output. Bidder
 * `j` owns the region at its tie priority.
 */
function vickreyPattern(report: RunResult): boolean[] {
  const { setup, outputSlots } = report
  const n = setup.bidders
  const levels = setup.levels
  const copyCount = copies(setup)
  const pattern: boolean[] = []
  for (let bidder = 0; bidder < n; bidder++) {
    const start = setup.tiePriority[bidder] * levels
    for (let position = start; position < start + levels; position++) {
      pattern.push(Array.from({ length: copyCount }, (_, copy) => copy).some((copy) => outputSlots[copy * n * levels + position] !== 0))
    }
  }
  return pattern
}

describe('the output depends only on the public result', () => {
  // Bid sets with the same result give the same zero pattern. The sets differ in the winning bid,
  // the runner-up, the number of bids at the price, and whether the top is a tie.
  for (const design of [vickrey, vickreyCompact]) {
    it(`${design.name}: same winner and price, same zero pattern`, () => {
      const rng = seededRng(5)
      // Bidder 1 has the highest priority, so it wins the tie in the third set.
      const priority = () => [2, 3, 0, 1]
      const sameResult = [
        [3, 12, 9, 9],
        [9, 15, 2, 9],
        [9, 9, 3, 5],
        [9, 10, 9, 0],
      ]
      const reports = sameResult.map((bids) => run(design, 'toy', bids, LEVELS, priority(), rng))
      for (const report of reports) {
        expect(report.result, `${design.name} on ${report.bids}`).toEqual({ winner: 1, price: 9 })
        expect(vickreyPattern(report), `${design.name} on ${report.bids}`).toEqual(vickreyPattern(reports[0]))
      }
      const otherWinner = run(design, 'toy', [9, 3, 12, 9], LEVELS, priority(), rng)
      expect(vickreyPattern(otherWinner)).not.toEqual(vickreyPattern(reports[0]))
    })
  }

  it('vickrey: the pattern shows the price level and the winner region, and nothing else', () => {
    // Winner region is zero from the price level s = 9 up. A loser region is zero from s + 1.
    const report = run(vickrey, 'toy', [3, 12, 9, 9], LEVELS, [2, 3, 0, 1], seededRng(5))
    const pattern = vickreyPattern(report)
    const regionOf = (bidder: number) => pattern.slice(bidder * LEVELS, (bidder + 1) * LEVELS)
    const winner = regionOf(1)
    const loser = regionOf(0)
    expect(winner.filter(Boolean).length).toBe(9)
    expect(loser.filter(Boolean).length).toBe(10)
    expect(winner.indexOf(false)).toBe(9)
    expect(loser.indexOf(false)).toBe(10)
  })

  // The output of the first-price program must not depend on the losing bids.
  it('first-price: the same slots for all bids with the same result', () => {
    const rng = seededRng(2)
    const a = run(firstPrice, 'toy', [2, 11, 6], LEVELS, undefined, rng)
    const b = run(firstPrice, 'toy', [10, 11, 0], LEVELS, undefined, rng)
    expect(a.result).toEqual(b.result)
    expect(a.outputCoefficients).toEqual(b.outputCoefficients)
    expect(a.outputSlots).toEqual(b.outputSlots)
  })

  // The only non-masked coefficient of second-price is coefficient 0. The masks have a zero
  // there, so two runs with the same result and other masks agree on c0 and differ elsewhere.
  it('second-price: only coefficient 0 is the same under other bids and other masks', () => {
    const a = run(secondPrice, 'toy', [2, 11, 6], LEVELS, undefined, seededRng(1))
    const b = run(secondPrice, 'toy', [3, 11, 6], LEVELS, undefined, seededRng(2))
    expect(a.result).toEqual(b.result)
    expect(a.outputCoefficients[0]).toBe(b.outputCoefficients[0])
    const different = a.outputCoefficients.filter((c, j) => j > 0 && c !== b.outputCoefficients[j]).length
    expect(different).toBeGreaterThan(1000)
  })
})

// A tie for the highest bid goes to the tied bidder with the highest tie priority, whatever its
// index.
describe('vickrey tie priority', () => {
  for (const design of [vickrey, vickreyCompact]) {
    it(`${design.name}: a tie goes to the tied bidder with the highest priority`, () => {
      const rng = seededRng(7)
      // Bidders 0, 2, and 3 tie at 9. Bidder 1 has a lower bid, so its priority does not count.
      const cases: [number[], number][] = [
        [[3, 0, 1, 2], 0],
        [[0, 3, 2, 1], 2],
        [[1, 2, 0, 3], 3],
      ]
      for (const [priority, winner] of cases) {
        const report = run(design, 'toy', [9, 3, 9, 9], LEVELS, priority, rng)
        expect(report.result, `${design.name} with priority ${priority}`).toEqual({ winner, price: 9 })
      }
    })
  }

  it('refuses a priority that is not a permutation, and a priority for a design that breaks ties by index', () => {
    expect(() => run(vickrey, 'toy', [9, 3, 9], LEVELS, [0, 0, 1])).toThrow(/permutation/)
    expect(() => run(firstPrice, 'toy', [9, 3, 9], LEVELS, [2, 1, 0])).toThrow(/by index/)
  })
})

/** The `kind` of the `SetupError` that `f` throws, or `'no error'`. Another error is rethrown. */
function setupErrorKind(f: () => unknown): string {
  try {
    f()
  } catch (error) {
    if (error instanceof SetupError) return error.kind
    throw error
  }
  return 'no error'
}

// The largest auction that fits the ring gives the right result; one more level is refused
// instead of giving a wrong result.
describe('slot limits', () => {
  // Toy ring: N = 1024 slots, 2 bidders.
  const limits: [AnyDesign, number][] = [
    [rank, Math.floor(1024 / 6)],
    [rankBatched, Math.floor(1024 / 12)],
    [firstPrice, 1024 / 2],
    [firstPriceBlind, 1024 / 2],
    [secondPrice, Math.floor(1024 / 3)],
    [secondPriceBlind, Math.floor(1024 / 3)],
    [vickrey, 1024 / 2],
    [vickreyCompact, 1024 / 2],
  ]
  for (const [design, levels] of limits) {
    it(`${design.name} runs at ${levels} levels and refuses ${levels + 1}`, () => {
      const rng = seededRng(3)
      const top = levels - 1
      expect(isCorrect(run(design, 'toy', [top, top], levels, undefined, rng))).toBe(true)
      expect(setupErrorKind(() => run(design, 'toy', [top, top], levels + 1, undefined, rng))).toBe('not-enough-slots')
    })
  }

  it('refuses a bid out of range, one bidder, and a depth the demo profile cannot hold', () => {
    expect(setupErrorKind(() => run(firstPrice, 'toy', [3, 16], LEVELS))).toBe('bid-out-of-range')
    expect(setupErrorKind(() => run(firstPrice, 'toy', [3], LEVELS))).toBe('too-few-bidders')
    // second-price: depth ⌈log2 33⌉ + 1 = 7 needs more log2(q) than the demo profile allows.
    expect(setupErrorKind(() => run(secondPrice, 'demo', new Array(33).fill(1), 4))).toBe('depth-too-large')
  })
})
