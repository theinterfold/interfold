// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { Profile } from '@designs'
import { MAX_BIDDERS, type Scenario } from './simulate'

/** The state of the controls. `bids` always has `MAX_BIDDERS` entries; only the first `bidders` count. */
export interface Params {
  profile: Profile
  bidders: number
  levels: number
  bids: number[]
  seed: number
  tieSeed: number
}

export const defaultParams: Params = {
  profile: 'toy',
  bidders: 4,
  levels: 8,
  bids: [2, 6, 3, 5, 1, 7, 4, 0, 5, 2, 7, 3, 1, 6, 4, 7],
  seed: 1,
  tieSeed: 1,
}

/** Applies a change, and keeps every bid inside `0..levels`. */
export function updateParams(params: Params, patch: Partial<Params>): Params {
  const next = { ...params, ...patch }
  return { ...next, bids: next.bids.map((bid) => Math.min(bid, next.levels - 1)) }
}

export function toScenario(params: Params): Scenario {
  const { profile, levels, seed, tieSeed } = params
  return { profile, levels, seed, tieSeed, bids: params.bids.slice(0, params.bidders) }
}

/** `MAX_BIDDERS` random bids in `0..levels`. */
export function randomBids(levels: number): number[] {
  return Array.from({ length: MAX_BIDDERS }, () => Math.floor(Math.random() * levels))
}

export function randomSeed(): number {
  return Math.floor(Math.random() * 1_000_000)
}
