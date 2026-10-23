// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * The simulation, as the viewer calls it. Every run is memoized: the same scenario gives the same
 * result, and the demo profile (N = 16384) takes noticeable time.
 */

import { designs, run, seededRng, shuffledIndices, type Profile, type RunResult } from '@designs'

export const MIN_BIDDERS = 2
export const MAX_BIDDERS = 16
export const MIN_LEVELS = 4
export const MAX_LEVELS = 16

/** Everything that fixes one simulated auction. */
export interface Scenario {
  profile: Profile
  /** One bid per bidder, each in `0..levels`. */
  bids: number[]
  levels: number
  /** Seed of the bidder masks. */
  seed: number
  /** Seed of the tie priority, for designs with `randomTieOrder`. */
  tieSeed: number
}

export type Outcome = { ok: true; run: RunResult } | { ok: false; error: Error }

/** The cost of the program of one design. It does not depend on the bids. */
export interface Cost {
  ciphertextProducts: number
  plaintextProducts: number
  depth: number
}

export type CostOutcome = { ok: true; cost: Cost } | { ok: false; error: Error }

const CACHE_LIMIT = 160
const outcomes = new Map<string, Outcome>()
const costs = new Map<string, CostOutcome>()

/** Returns the cached value of `key`, or computes it. The oldest entries go first. */
function memoize<V>(cache: Map<string, V>, key: string, compute: () => V): V {
  const hit = cache.get(key)
  if (hit !== undefined) return hit
  const value = compute()
  cache.set(key, value)
  if (cache.size > CACHE_LIMIT) cache.delete(cache.keys().next().value as string)
  return value
}

function attempt<V>(compute: () => V): { ok: true; value: V } | { ok: false; error: Error } {
  try {
    return { ok: true, value: compute() }
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error : new Error(String(error)) }
  }
}

/** The tie priority of bidder `i` is `priority[i]`. A higher priority wins a tie. */
export function drawTiePriority(bidders: number, tieSeed: number): number[] {
  return shuffledIndices(bidders, seededRng(tieSeed))
}

/** Runs one design on a scenario. A design with `randomTieOrder` gets the priority of `tieSeed`. */
export function simulate(designName: string, scenario: Scenario, trace: boolean): Outcome {
  const { profile, bids, levels, seed, tieSeed } = scenario
  const key = [designName, profile, levels, seed, tieSeed, trace, bids.join(',')].join('|')
  return memoize(outcomes, key, () => {
    const design = designs[designName]
    const priority = design.randomTieOrder ? drawTiePriority(bids.length, tieSeed) : undefined
    const result = attempt(() => run(design, profile, bids, levels, priority, seededRng(seed), { trace }))
    return result.ok ? { ok: true, run: result.value } : result
  })
}

/** Measures the program of one design for `bidders` bidders. Any valid bids give the same counts. */
export function measureCost(designName: string, profile: Profile, bidders: number, levels: number): CostOutcome {
  const key = [designName, profile, bidders, levels].join('|')
  return memoize(costs, key, () => {
    const bids = Array.from({ length: bidders }, (_, i) => i % levels)
    const result = attempt(() => run(designName, profile, bids, levels))
    if (!result.ok) return result
    const { opCounts, depth } = result.value
    return { ok: true, cost: { ciphertextProducts: opCounts.ciphertextProducts, plaintextProducts: opCounts.plaintextProducts, depth } }
  })
}

/** The largest bidder count, up to `MAX_BIDDERS`, that the profile accepts at this many levels. */
export function maxBidders(designName: string, profile: Profile, levels: number): number | null {
  for (let bidders = MAX_BIDDERS; bidders >= MIN_BIDDERS; bidders--) {
    if (measureCost(designName, profile, bidders, levels).ok) return bidders
  }
  return null
}
