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
 * The output slots of the provider type on the plaintext bids. `maskOf(slot)` is the product `r`
 * of the masks at `slot` (1..256), and zero slots stay zero. One copy: region `k` is the slots
 * `16 k .. 16 k + 15`, and the slots from `16 n` on are zero.
 */
function providerSlots(bids: readonly number[], maskOf: (slot: number) => bigint = () => 1n): bigint[] {
  const n = bids.length
  const slots = new Array<bigint>(DEGREE).fill(0n)
  for (let k = 0; k < n; k++) {
    for (let level = 0; level < LEVELS; level++) {
      const othersAbove = count(
        bids.filter((_, j) => j !== k),
        (bid) => bid > level,
      )
      const earlierTies = count(bids.slice(0, k), (bid) => bid === level)
      const atLeast = count(bids, (bid) => bid >= level)
      const test = (othersAbove + (bids[k] < level ? 1 : 0) + (bids[k] === level ? earlierTies : 0)) * atLeast * (atLeast - 1)
      const slot = slotIndex(k, level)
      slots[slot] = (BigInt(test) * maskOf(slot)) % T
    }
  }
  return slots
}

describe('expectedResult', () => {
  it.each(ROUNDS)('picks the earliest position of a tie at the top: %j', (bids, winner) => {
    expect(expectedResult(bids).winner).toBe(winner)
  })

  it('gives the second-highest bid as the price, with up to 8 bidders', () => {
    expect(expectedResult([5, 12, 9])).toEqual({ winner: 1, price: 9 })
    expect(expectedResult([7, 3, 7])).toEqual({ winner: 0, price: 7 })
    expect(expectedResult([2, 3, 9, 1, 9, 9, 0, 9])).toEqual({ winner: 2, price: 9 })
    expect(() => expectedResult([1])).toThrow()
    expect(() => expectedResult([1, 2, 3, 4, 5, 6, 7, 8, 9])).toThrow()
  })
})

describe('encodeParams', () => {
  it('encodes the type 2 with no providers and no gate', () => {
    const abi = parseAbiParameters('uint8, uint8, uint256[16], string, address, bytes, address[]')
    const [type, levels, , title, gate, , providers] = decodeAbiParameters(abi, encodeParams([1n, 2n, 5n], 'Lot'))
    expect(type).toBe(2)
    expect(levels).toBe(3)
    expect(title).toBe('Lot')
    expect(gate).toBe(zeroAddress)
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
  /** `r = (S1^2 - 3) * (S2^2 - 3) mod t` for the share sums `S1` and `S2`. */
  const factor = (s1: bigint, s2: bigint) => (((((s1 * s1 - 3n) % T) + T) % T) * ((((s2 * s2 - 3n) % T) + T) % T)) % T

  beforeEach(() => {
    outputSlots = []
  })

  it('has a factor `(S1^2 - 3) * (S2^2 - 3)` that is never zero: 3 is not a square modulo t', () => {
    for (let s = 0n; s < T; s++) expect((s * s) % T).not.toBe(3n)
    for (let s1 = 0n; s1 < T; s1++) expect(factor(s1, (s1 * 5n + 1n) % T)).not.toBe(0n)
  })

  it.each(ROUNDS)('reads the winner and the price of %j', async (bids, winner) => {
    const result = await decode(providerSlots(bids), bids.length)
    expect(result).toMatchObject({ winner, price: expectedResult(bids).price, unusedGroupsZero: true })
  })

  it('reads the same result under the factor of every pair of share sums', async () => {
    for (let shift = 0n; shift < T; shift += 16n) {
      // The sums of the slots go through every value of 0..t over the shifts.
      const maskOf = (slot: number) => factor(BigInt(slot) + shift, 2n * BigInt(slot) + shift)
      for (const [bids, winner] of ROUNDS) {
        expect(await decode(providerSlots(bids, maskOf), bids.length)).toMatchObject({ winner, price: expectedResult(bids).price })
      }
    }
  })

  it('reads a tie at the top as a unique top: the pattern is the same', async () => {
    const tied = await decode(providerSlots([9, 9, 0]), 3)
    const unique = await decode(providerSlots([15, 9, 0]), 3)
    expect(tied).toMatchObject({ winner: 0, price: 9 })
    expect(tied).toEqual(unique)
  })

  it('rejects a pattern that is not the one of a winner and a price', async () => {
    const base = () => providerSlots([5, 12, 9])
    const at = (region: number, level: number) => slotIndex(region, level)
    const beyond = base()
    beyond[3 * LEVELS] = 1n
    expect(await decode(beyond, 3)).toMatchObject({ ...invalid, unusedGroupsZero: false })
    const hole = base()
    hole[at(2, 4)] = 0n
    expect(await decode(hole, 3)).toMatchObject(invalid)
    const noWinner = base()
    noWinner[at(1, 9)] = 7n
    expect(await decode(noWinner, 3)).toMatchObject(invalid)
    const twoWinners = base()
    twoWinners[at(0, 9)] = 0n
    expect(await decode(twoWinners, 3)).toMatchObject(invalid)
    expect(await decode(new Array<bigint>(DEGREE).fill(0n), 3)).toMatchObject(invalid)
  })

  it('refuses a bidder count outside 2 to 8', async () => {
    await expect(decode(providerSlots([1, 2]), 1)).rejects.toThrow()
    await expect(decode(providerSlots([1, 2]), 9)).rejects.toThrow()
  })
})
