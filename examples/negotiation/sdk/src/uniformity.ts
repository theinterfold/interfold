// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * The exact law of the agreed price. For a seller step `s` and a buyer step `b` (with `s <= b`), the pointer
 * `u = a xor c` is uniform on 0..15 whenever one share is uniform, and the price level is the least
 * `l xor u` in `[s, b]`. So `likelihood(levels)[s][b][p]` is the exact probability of the level `p`
 * (a multiple of 1/16). The ideal mechanism has `1 / (b - s + 1)` on every level of `[s, b]`.
 */
import { LANES, LEVELS } from './layout'

/** `likelihood[s][b][p]`: the exact probability that the agreed level is `p`, for `s <= b < levels`. */
export function likelihood(levels: number = LEVELS): number[][][] {
  const table: number[][][] = []
  for (let s = 0; s < levels; s++) {
    table.push([])
    for (let b = 0; b < levels; b++) {
      const law = new Array<number>(levels).fill(0)
      if (s <= b) {
        for (let u = 0; u < LANES; u++) {
          let best = s
          for (let i = s; i <= b; i++) if ((i ^ u) < (best ^ u)) best = i
          law[best] += 1 / LANES
        }
      }
      table[s].push(law)
    }
  }
  return table
}

/** How far a negotiation mechanism is from the ideal one, over every interval `[s, b]` with the same weight. */
export interface Metrics {
  /** The largest total variation distance to the uniform law on an interval. */
  maxTv: number
  /** The mean of that distance over all intervals. */
  meanTv: number
  /** The interval that reaches `maxTv`. */
  worst: { s: number; b: number }
  /** The largest `P(p) * n` over the levels of an interval of `n` levels (1 for the ideal). */
  overweight: number
  /** The least `P(p) * n` over the levels that have a positive probability. */
  underweight: number
  /** The number of (interval, level) pairs with level in the interval and probability 0: a level that the output excludes. */
  excluded: number
  /** `I(price; (s, b))` in bits, for a uniform prior over the intervals. */
  mutualInformation: number
  /** The same for the ideal mechanism. */
  idealMutualInformation: number
}

/** The metrics of a likelihood table. */
export function metrics(table: number[][][], levels: number = LEVELS): Metrics {
  const pairs: [number, number][] = []
  for (let s = 0; s < levels; s++) for (let b = s; b < levels; b++) pairs.push([s, b])
  let maxTv = 0
  let sumTv = 0
  let worst = { s: 0, b: 0 }
  let overweight = 0
  let underweight = Infinity
  let excluded = 0
  for (const [s, b] of pairs) {
    const n = b - s + 1
    let tv = 0
    for (let p = 0; p < levels; p++) {
      const probability = table[s][b][p]
      const ideal = p >= s && p <= b ? 1 / n : 0
      tv += Math.abs(probability - ideal) / 2
      if (p >= s && p <= b) {
        if (probability === 0) excluded++
        else {
          overweight = Math.max(overweight, probability * n)
          underweight = Math.min(underweight, probability * n)
        }
      }
    }
    sumTv += tv
    if (tv > maxTv) {
      maxTv = tv
      worst = { s, b }
    }
  }
  return {
    maxTv,
    meanTv: sumTv / pairs.length,
    worst,
    overweight,
    underweight,
    excluded,
    mutualInformation: mutualInformation(pairs, (s, b, p) => table[s][b][p], levels),
    idealMutualInformation: mutualInformation(pairs, (s, b, p) => (p >= s && p <= b ? 1 / (b - s + 1) : 0), levels),
  }
}

function mutualInformation(pairs: [number, number][], law: (s: number, b: number, p: number) => number, levels: number): number {
  const marginal = new Array<number>(levels).fill(0)
  for (const [s, b] of pairs) for (let p = 0; p < levels; p++) marginal[p] += law(s, b, p) / pairs.length
  let bits = 0
  for (const [s, b] of pairs) {
    for (let p = 0; p < levels; p++) {
      const probability = law(s, b, p)
      if (probability > 0) bits += (probability / pairs.length) * Math.log2(probability / marginal[p])
    }
  }
  return bits
}

/** What the seller (who knows `s`) believes about `b` after the output `p`, for a uniform prior on `b >= s`: `P(b | s, p)`. */
export function sellerPosterior(table: number[][][], levels: number, s: number, p: number): number[] {
  const weights = new Array<number>(levels).fill(0)
  let total = 0
  for (let b = s; b < levels; b++) {
    weights[b] = table[s][b][p]
    total += weights[b]
  }
  return weights.map((weight) => (total > 0 ? weight / total : 0))
}

/** The same for the buyer (who knows `b`): `P(s | b, p)`. */
export function buyerPosterior(table: number[][][], levels: number, b: number, p: number): number[] {
  const weights = new Array<number>(levels).fill(0)
  let total = 0
  for (let s = 0; s <= b; s++) {
    weights[s] = table[s][b][p]
    total += weights[s]
  }
  return weights.map((weight) => (total > 0 ? weight / total : 0))
}
