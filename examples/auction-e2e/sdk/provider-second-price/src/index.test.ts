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

import { decodeAbiParameters, parseAbiParameters, zeroAddress, type Address } from 'viem'
import { DEGREE, LEVELS, PLAINTEXT_MODULUS, slotIndex } from '@interfold/auction-core'
import { decodeResult, encodeParams, expectedResult } from './index'

const PROVIDER_A: Address = '0x1111111111111111111111111111111111111111'
const PROVIDER_B: Address = '0x2222222222222222222222222222222222222222'

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
  const abi = parseAbiParameters('uint8, uint8, uint256[16], string, address, bytes, address[]')

  it('encodes the type 1 with the providers in the given order', () => {
    const gate: Address = '0x9999999999999999999999999999999999999999'
    const encoded = encodeParams([1n, 2n, 5n], 'Lot 4', [PROVIDER_B, PROVIDER_A], gate, '0x1234')
    const [type, levels, , title, decodedGate, gateConfig, providers] = decodeAbiParameters(abi, encoded)
    expect(type).toBe(1)
    expect(levels).toBe(3)
    expect(title).toBe('Lot 4')
    expect(decodedGate.toLowerCase()).toBe(gate)
    expect(gateConfig).toBe('0x1234')
    expect(providers.map((provider) => provider.toLowerCase())).toEqual([PROVIDER_B, PROVIDER_A])
  })

  it('has no gate by default', () => {
    const [, , , , gate] = decodeAbiParameters(abi, encodeParams([1n, 2n], 'Lot', [PROVIDER_A]))
    expect(gate).toBe(zeroAddress)
  })

  it('refuses no provider, a duplicate and an invalid price list', () => {
    expect(() => encodeParams([1n, 2n], 'Lot', [])).toThrow()
    expect(() => encodeParams([1n, 2n], 'Lot', [PROVIDER_A, PROVIDER_A])).toThrow()
    expect(() => encodeParams([2n, 1n], 'Lot', [PROVIDER_A])).toThrow()
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

  it.each(ROUNDS)('reads the winner and the price of %j', async (bids, winner) => {
    const result = await decode(providerSlots(bids), bids.length)
    expect(result).toMatchObject({ winner, price: expectedResult(bids).price, unusedGroupsZero: true })
  })

  it('reads the same result under every non-zero mask', async () => {
    // A ramp through 1..256 and a constant 256: a non-zero test never becomes zero.
    for (const maskOf of [(slot: number) => BigInt((slot * 7) % 256) + 1n, () => T - 1n]) {
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

  it('reads bid 0 everywhere: the first bidder wins at price 0', async () => {
    expect(await decode(providerSlots([0, 0]), 2)).toMatchObject({ winner: 0, price: 0 })
    expect(await decode(providerSlots([0, 0, 0, 0, 0, 0, 0, 0]), 8)).toMatchObject({ winner: 0, price: 0 })
    expect(await decode(providerSlots([0, 0, 0, 5]), 4)).toMatchObject({ winner: 3, price: 0 })
  })

  it('shows the set pattern: zero above the price, the winner clear at the price', async () => {
    const result = await decode(providerSlots([5, 12, 9]), 3)
    expect(result.winner).toBe(1)
    expect(result.set[1]).toEqual(Array.from({ length: LEVELS }, (_, level) => level < 9))
    expect(result.set[0]).toEqual(Array.from({ length: LEVELS }, (_, level) => level <= 9))
    expect(result.set[2]).toEqual(result.set[0])
  })

  describe('rejects every pattern that is not the one of a winner and a price', () => {
    const base = () => providerSlots([5, 12, 9])
    const at = (region: number, level: number) => slotIndex(region, level)

    it('with a non-zero slot beyond the regions', async () => {
      const slots = base()
      slots[3 * LEVELS] = 1n
      expect(await decode(slots, 3)).toMatchObject({ ...invalid, unusedGroupsZero: false })
    })

    it('with a zero slot below the price', async () => {
      const slots = base()
      slots[at(2, 4)] = 0n
      expect(await decode(slots, 3)).toMatchObject(invalid)
    })

    it('with a non-zero slot above the price in one region only', async () => {
      const slots = base()
      slots[at(1, 14)] = 5n
      // The price moves to level 14, where every region is zero but region 1, so region 1 is the
      // only non-zero one: two regions are clear, and levels below 14 are not all set.
      expect(await decode(slots, 3)).toMatchObject(invalid)
    })

    it('with no zero region at the price', async () => {
      const slots = base()
      slots[at(1, 9)] = 7n
      expect(await decode(slots, 3)).toMatchObject(invalid)
    })

    it('with two zero regions at the price', async () => {
      const slots = base()
      slots[at(0, 9)] = 0n
      expect(await decode(slots, 3)).toMatchObject(invalid)
    })

    it('with every slot zero', async () => {
      expect(await decode(new Array<bigint>(DEGREE).fill(0n), 3)).toMatchObject(invalid)
    })

    it('with every region non-zero everywhere', async () => {
      const slots = new Array<bigint>(DEGREE).fill(0n)
      for (let slot = 0; slot < 3 * LEVELS; slot++) slots[slot] = 1n
      expect(await decode(slots, 3)).toMatchObject(invalid)
    })

    it('with a slot above the price set in a used region while the others are zero', async () => {
      const slots = providerSlots([3, 3, 3])
      slots[at(2, 8)] = 1n
      expect(await decode(slots, 3)).toMatchObject(invalid)
    })
  })

  it('refuses a bidder count outside 2 to 8', async () => {
    await expect(decode(providerSlots([1, 2]), 1)).rejects.toThrow()
    await expect(decode(providerSlots([1, 2]), 9)).rejects.toThrow()
  })
})
