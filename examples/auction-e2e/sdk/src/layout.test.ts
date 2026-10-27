// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { beforeEach, describe, expect, it, vi } from 'vitest'

// The SIMD slots of the published output. `decodePlaintextSlots` needs the wasm module of the
// Interfold SDK, so the tests pass the slots in directly and exercise the decoders of `layout.ts`.
let outputSlots: bigint[] = []
vi.mock('@interfold/sdk', () => ({ decodePlaintextSlots: async () => outputSlots }))

import {
  AuctionType,
  DEGREE,
  LEVELS,
  PLAINTEXT_MODULUS,
  RATIO_COPIES,
  copiesFor,
  decodeAuction,
  expectedAuction,
  expectedTieSet,
  slotIndex,
} from './layout'

const T = BigInt(PLAINTEXT_MODULUS)
/** The hex of a plaintext output. The mocked decoder ignores its value. */
const OUTPUT = `0x${'00'.repeat(128 * 8)}`

/** Bid sets with the winner position: unique tops at every position, and tops that tie. */
const ROUNDS: ReadonlyArray<readonly [readonly number[], number]> = [
  [[12, 5, 9], 0],
  [[5, 12, 9], 1],
  [[5, 9, 12], 2],
  [[7, 3, 7], 0],
  [[3, 7, 7], 1],
  [[7, 7, 7], 0],
  [[5, 9, 2, 9], 1],
  [[4, 4], 0],
]
/** Ratio-lane rounds with more than 4 bidders. */
const RATIO_ROUNDS: ReadonlyArray<readonly [readonly number[], number]> = [
  [[2, 3, 9, 1, 9, 9, 0, 9], 2],
  [[15, 15, 15, 15, 15, 15, 15, 15], 0],
  [[0, 0, 0, 0, 0, 0, 15, 15], 6],
]

const count = (bids: readonly number[], test: (bid: number) => boolean) => bids.filter(test).length

/**
 * The output slots of a region type on the plaintext bids with every mask equal to 1: the test
 * vector of `program/src/lib.rs`. Region `k` is the region of bidder position `k`.
 */
function regionSlots(type: AuctionType, bids: readonly number[]): bigint[] {
  const n = bids.length
  const slots = new Array<bigint>(DEGREE).fill(0n)
  for (let copy = 0; copy < copiesFor(n); copy++) {
    for (let k = 0; k < n; k++) {
      for (let level = 0; level < LEVELS; level++) {
        const othersAbove = count(bids.filter((_, j) => j !== k), (bid) => bid > level)
        const earlierTies = count(bids.slice(0, k), (bid) => bid === level)
        let test: number
        if (type === AuctionType.FirstPrice) {
          test = (bids[k] === level ? 0 : 1) + othersAbove + earlierTies
        } else {
          const atLeast = count(bids, (bid) => bid >= level)
          test = (othersAbove + (bids[k] < level ? 1 : 0) + (bids[k] === level ? earlierTies : 0)) * atLeast * (atLeast - 1)
        }
        slots[slotIndex(n, copy, k, level)] = BigInt(test) % T
      }
    }
  }
  return slots
}

/**
 * The output slots of a ratio-lane type on the plaintext bids with every mask and the pair mask
 * equal to 1: the lanes of `program/src/lib.rs`.
 */
function laneSlots(type: AuctionType, bids: readonly number[]): bigint[] {
  const slots = new Array<bigint>(DEGREE).fill(0n)
  const weightOf = (test: (bid: number) => boolean) => bids.reduce((sum, bid, k) => sum + (test(bid) ? 1n << BigInt(k) : 0n), 0n)
  for (let level = 0; level < LEVELS; level++) {
    const atLeastCount = BigInt(count(bids, (bid) => bid >= level))
    const aboveCount = BigInt(count(bids, (bid) => bid > level))
    const atLeast = weightOf((bid) => bid >= level)
    const above = weightOf((bid) => bid > level)
    if (type === AuctionType.RatioFirstPrice) {
      slots[level] = (atLeast + aboveCount) % T
      continue
    }
    const c = atLeastCount * (atLeastCount - 1n)
    const u = aboveCount * (aboveCount - 1n)
    const winners = above + (1n - aboveCount) * (atLeast - above)
    for (let copy = 0; copy < RATIO_COPIES; copy++) {
      slots[2 * copy * LEVELS + level] = (c + u) % T
      slots[(2 * copy + 1) * LEVELS + level] = (((c * winners) % T) + u + T) % T
    }
  }
  return slots
}

describe('expectedAuction', () => {
  it.each(ROUNDS)('picks the earliest position of a tie at the top: %j', (bids, winner) => {
    for (const type of [AuctionType.FirstPrice, AuctionType.SecondPrice, AuctionType.RatioFirstPrice, AuctionType.RatioSecondPrice]) {
      expect(expectedAuction(type, bids).winner).toBe(winner)
    }
  })

  it('prices a tie at the top at the tied bid, and a unique top by its type', () => {
    expect(expectedAuction(AuctionType.SecondPrice, [7, 3, 7])).toEqual({ winner: 0, price: 7 })
    expect(expectedAuction(AuctionType.FirstPrice, [7, 3, 7])).toEqual({ winner: 0, price: 7 })
    expect(expectedAuction(AuctionType.SecondPrice, [5, 12, 9])).toEqual({ winner: 1, price: 9 })
    expect(expectedAuction(AuctionType.FirstPrice, [5, 12, 9])).toEqual({ winner: 1, price: 12 })
  })
})

describe('decodeAuction', () => {
  beforeEach(() => {
    outputSlots = []
  })

  describe.each([AuctionType.FirstPrice, AuctionType.SecondPrice])('region type %i', (type) => {
    it.each(ROUNDS)('names the earliest tied bidder as the winner: %j', async (bids, winner) => {
      outputSlots = regionSlots(type, bids)
      const result = await decodeAuction(type, OUTPUT, bids.length)
      expect(result).toMatchObject({ kind: 'region', winner, price: expectedAuction(type, bids).price, unusedGroupsZero: true })
    })

    it('does not show a tie: the same winner and price give the same set pattern', async () => {
      // Winner 0 at price 9: a tie at 9 and a unique top above the runner-up at 9 (second-price)
      // or at 9 (first-price).
      const [tie, unique] = type === AuctionType.FirstPrice ? [[9, 9, 0], [9, 4, 0]] : [[9, 9, 0], [15, 9, 0]]
      outputSlots = regionSlots(type, tie)
      const tied = await decodeAuction(type, OUTPUT, 3)
      outputSlots = regionSlots(type, unique)
      const single = await decodeAuction(type, OUTPUT, 3)
      expect(tied).toMatchObject({ winner: 0, price: 9 })
      expect(tied).toEqual(single)
    })
  })

  describe.each([AuctionType.RatioFirstPrice, AuctionType.RatioSecondPrice])('ratio-lane type %i', (type) => {
    it.each([...ROUNDS, ...RATIO_ROUNDS])('names the first member of the tie set as the winner: %j', async (bids, winner) => {
      outputSlots = laneSlots(type, bids)
      const result = await decodeAuction(type, OUTPUT, bids.length)
      const { price, tieSet } = expectedTieSet(type, bids)
      expect(result).toMatchObject({ kind: 'lane', price, tieSet, winner, copiesAgree: true })
      expect(tieSet[0]).toBe(winner)
    })

    it('reads no winner when there is no price', async () => {
      outputSlots = new Array<bigint>(DEGREE).fill(0n)
      expect(await decodeAuction(type, OUTPUT, 3)).toMatchObject({ price: null, winner: null, tieSet: [] })
    })
  })
})
