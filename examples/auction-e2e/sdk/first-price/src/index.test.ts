// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { beforeEach, describe, expect, it, vi } from 'vitest'

// The SIMD slots of the published output. `decodePlaintextSlots` needs the wasm module of the
// Interfold SDK, so the tests pass the slots in directly and exercise the decoder of this package.
let outputSlots: bigint[] = []
vi.mock('@interfold/sdk', () => ({ decodePlaintextSlots: async () => outputSlots }))

import { decodeAbiParameters, parseAbiParameters, zeroAddress } from 'viem'
import { DEGREE, LEVELS, PLAINTEXT_MODULUS, slotIndex } from '@interfold/auction-core'
import { decodeResult, encodeParams, expectedResult } from './index'

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
  [[2, 3, 9, 1, 9, 9, 0, 9], 2],
  [[15, 15, 15, 15, 15, 15, 15, 15], 0],
  [[0, 0, 0, 0, 0, 0, 15, 15], 6],
]

const count = (bids: readonly number[], test: (bid: number) => boolean) => bids.filter(test).length
/**
 * The output slots of the first-price type on the plaintext bids: `ge + m * (G + E)` in each slot of
 * `program/src/lib.rs`, with `m` the sum of the bidder masks at the slot (`maskOf(slot)`, in `[0, t)`).
 * Region `k` is the region of bidder position `k`, and the slots from `16 n` on are zero.
 */
function firstPriceSlots(bids: readonly number[], maskOf: (slot: number) => bigint = () => 1n): bigint[] {
  const slots = new Array<bigint>(DEGREE).fill(0n)
  for (let k = 0; k < bids.length; k++) {
    for (let level = 0; level < LEVELS; level++) {
      const above = count(bids, (bid) => bid > level)
      const earlierTies = count(bids.slice(0, k), (bid) => bid === level)
      const slot = slotIndex(k, level)
      slots[slot] = (BigInt(bids[k] >= level) + maskOf(slot) * BigInt(above + earlierTies)) % T
    }
  }
  return slots
}

describe('expectedResult', () => {
  it.each(ROUNDS)('picks the earliest position of a tie at the top: %j', (bids, winner) => {
    expect(expectedResult(bids).winner).toBe(winner)
  })

  it('prices the highest bid, also for a tie at the top', () => {
    expect(expectedResult([7, 3, 7])).toEqual({ winner: 0, price: 7 })
    expect(expectedResult([5, 12, 9])).toEqual({ winner: 1, price: 12 })
  })

  it('refuses a bidder count outside 2 to 8', () => {
    expect(() => expectedResult([1])).toThrow()
    expect(() => expectedResult([1, 2, 3, 4, 5, 6, 7, 8, 9])).toThrow()
  })
})

describe('encodeParams', () => {
  it('encodes the type 0 with no providers and no gate', () => {
    const abi = parseAbiParameters('uint8, uint8, uint256[16], string, address, bytes, address[]')
    const [type, levels, , title, gate, gateConfig, providers] = decodeAbiParameters(abi, encodeParams([1n, 2n, 5n], 'Lot'))
    expect(type).toBe(0)
    expect(levels).toBe(3)
    expect(title).toBe('Lot')
    expect(gate).toBe(zeroAddress)
    expect(gateConfig).toBe('0x')
    expect(providers).toEqual([])
  })

  it('refuses an invalid price list', () => {
    expect(() => encodeParams([2n, 1n], 'Lot')).toThrow()
  })
})

describe('decodeResult', () => {
  const decode = async (slots: bigint[], n: number) => {
    outputSlots = slots
    return decodeResult(OUTPUT, n)
  }
  const invalid = { price: null, winner: null }

  beforeEach(() => {
    outputSlots = []
  })

  it.each(ROUNDS)('reads the earliest tied bidder as the winner, and the highest bid as the price: %j', async (bids, winner) => {
    const result = await decode(firstPriceSlots(bids), bids.length)
    expect(result).toMatchObject({ winner, price: expectedResult(bids).price, unusedGroupsZero: true })
  })

  it('reads the same result under every mask, also a mask that is zero in every slot', async () => {
    const masks = [() => 0n, (slot: number) => BigInt((slot * 7) % PLAINTEXT_MODULUS), () => T - 1n, () => 1n]
    for (const maskOf of masks) {
      for (const [bids, winner] of ROUNDS) {
        expect(await decode(firstPriceSlots(bids, maskOf), bids.length)).toMatchObject({ winner, price: expectedResult(bids).price })
      }
    }
  })

  it('shows zero above the price, and before the winner at the price (bids 5, 12, 9)', async () => {
    const result = await decode(firstPriceSlots([5, 12, 9]), 3)
    expect(result).toMatchObject({ winner: 1, price: 12 })
    for (const row of result.set) expect(row.slice(13)).toEqual([false, false, false])
    expect(result.set[1][12]).toBe(true)
    // The lane before the winner is zero at the price. The lane after it holds the bid of the winner
    // as an earlier tie, so it is masked and may hold anything.
    expect(result.set[0][12]).toBe(false)
  })

  it('reads a lane after the winner at the price whatever it holds', async () => {
    // Bids 9, 9, 0: lane 1 holds 1 + m * 1 at level 9, and lane 0 holds exactly 1.
    for (const maskOf of [() => 0n, () => 1n, () => T - 1n]) {
      expect(await decode(firstPriceSlots([9, 9, 0], maskOf), 3)).toMatchObject({ winner: 0, price: 9 })
    }
  })

  describe('rejects every pattern that is not the one of a winner and a price', () => {
    const base = () => firstPriceSlots([5, 12, 9])
    const at = (region: number, level: number) => slotIndex(region, level)

    it('with a non-zero slot beyond the regions', async () => {
      const slots = base()
      slots[3 * LEVELS] = 1n
      expect(await decode(slots, 3)).toMatchObject({ ...invalid, unusedGroupsZero: false })
    })

    it('with a winner slot at the price that is not exactly 1', async () => {
      const slots = base()
      slots[at(1, 12)] = 2n
      expect(await decode(slots, 3)).toMatchObject(invalid)
    })

    it('with an earlier region that holds another value than 1 at the price', async () => {
      const slots = base()
      slots[at(0, 12)] = 3n
      expect(await decode(slots, 3)).toMatchObject(invalid)
    })

    it('with a non-zero slot above the price', async () => {
      const slots = base()
      slots[at(2, 14)] = 5n
      expect(await decode(slots, 3)).toMatchObject(invalid)
    })

    it('with every slot zero', async () => {
      expect(await decode(new Array<bigint>(DEGREE).fill(0n), 3)).toMatchObject(invalid)
    })
  })

  it('refuses a bidder count outside 2 to 8', async () => {
    await expect(decode(firstPriceSlots([1, 2]), 1)).rejects.toThrow()
    await expect(decode(firstPriceSlots([1, 2]), 9)).rejects.toThrow()
  })
})
