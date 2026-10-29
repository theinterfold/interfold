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

import { decodeAbiParameters, keccak256, parseAbiParameters, zeroAddress, type Address } from 'viem'
import {
  AUCTION_TYPES,
  AUCTION_TYPE_LABELS,
  AuctionType,
  bidSlots,
  DEGREE,
  LEVELS,
  MASK_VERSION,
  MAX_BIDDERS_BY_TYPE,
  MAX_PROVIDERS,
  PLAINTEXT_MODULUS,
  RATIO_COPIES,
  Role,
  auctionConfigInput,
  copiesFor,
  decodeAuction,
  encodeAuctionParams,
  encodeBidInput,
  encodeMaskInput,
  expectedAuction,
  expectedTieSet,
  isProviderType,
  providersError,
  rolesFor,
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
        const othersAbove = count(
          bids.filter((_, j) => j !== k),
          (bid) => bid > level,
        )
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
      const [tie, unique] =
        type === AuctionType.FirstPrice
          ? [
              [9, 9, 0],
              [9, 4, 0],
            ]
          : [
              [9, 9, 0],
              [15, 9, 0],
            ]
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

/** The first two addresses of the config vector that `AuctionProgram.configInput` and the program also assert. */
const PROVIDER_A: Address = '0x1111111111111111111111111111111111111111'
const PROVIDER_B: Address = '0x2222222222222222222222222222222222222222'
const PROVIDER_C: Address = '0x3333333333333333333333333333333333333333'
const PROVIDER_D: Address = '0x4444444444444444444444444444444444444444'
const PROVIDER_E: Address = '0x5555555555555555555555555555555555555555'

describe('the provider-mask type', () => {
  it('has 2 roles, up to 8 bidders and its own label', () => {
    const type = AuctionType.ProviderSecondPrice
    expect(type).toBe(4)
    expect(AUCTION_TYPES).toContain(type)
    expect(AUCTION_TYPE_LABELS[type]).toBe('Second-price, zero failure')
    expect(rolesFor(type)).toEqual([Role.Ge, Role.Gt])
    expect(MAX_BIDDERS_BY_TYPE[type]).toBe(8)
    expect(isProviderType(type)).toBe(true)
    for (const other of [AuctionType.FirstPrice, AuctionType.SecondPrice, AuctionType.RatioFirstPrice, AuctionType.RatioSecondPrice]) {
      expect(isProviderType(other)).toBe(false)
    }
    expect(MAX_PROVIDERS).toBe(4)
    expect(MASK_VERSION).toBe(0xffffffff)
  })

  it('gives the result of the second-price type, with up to 8 bidders', () => {
    for (const [bids] of ROUNDS) {
      expect(expectedAuction(AuctionType.ProviderSecondPrice, bids)).toEqual(expectedAuction(AuctionType.SecondPrice, bids))
    }
    expect(expectedAuction(AuctionType.ProviderSecondPrice, [2, 3, 9, 1, 9, 9, 0, 9])).toEqual({ winner: 2, price: 9 })
    expect(() => expectedAuction(AuctionType.ProviderSecondPrice, [1])).toThrow()
    expect(() => expectedAuction(AuctionType.ProviderSecondPrice, [1, 2, 3, 4, 5, 6, 7, 8, 9])).toThrow()
  })
})

describe('auctionConfigInput', () => {
  it('has no providers for the types 0 to 3: the domain and the type byte', () => {
    for (const type of [AuctionType.FirstPrice, AuctionType.SecondPrice, AuctionType.RatioFirstPrice, AuctionType.RatioSecondPrice]) {
      expect(auctionConfigInput(type)).toBe(`0x${Buffer.from('interfold-auction-config-v1').toString('hex')}0${type}`)
    }
    expect(keccak256(auctionConfigInput(AuctionType.SecondPrice))).toBe(
      keccak256(`0x${Buffer.from('interfold-auction-config-v1\x01').toString('hex')}`),
    )
  })

  it('matches the vector of AuctionProgram.configInput for 2 providers: 20 raw bytes each', () => {
    const input = auctionConfigInput(AuctionType.ProviderSecondPrice, [PROVIDER_A, PROVIDER_B])
    expect(input).toBe(
      '0x696e746572666f6c642d61756374696f6e2d636f6e6669672d76310411111111111111111111111111111111111111112222222222222222222222222222222222222222',
    )
    expect((input.length - 2) / 2).toBe(68)
    expect(keccak256(input)).toBe('0xc6399fdb7f3b0e098dc01996306af62f928ed18203a1920ba1a7c96379d6460c')
  })

  it('does not depend on the case of an address, and keeps the order', () => {
    const lower = auctionConfigInput(AuctionType.ProviderSecondPrice, [PROVIDER_A, '0xabcdef0000000000000000000000000000000001'])
    const mixed = auctionConfigInput(AuctionType.ProviderSecondPrice, [PROVIDER_A, '0xABCDEF0000000000000000000000000000000001'])
    expect(mixed).toBe(lower)
    expect(auctionConfigInput(AuctionType.ProviderSecondPrice, [PROVIDER_B, PROVIDER_A])).not.toBe(
      auctionConfigInput(AuctionType.ProviderSecondPrice, [PROVIDER_A, PROVIDER_B]),
    )
  })

  it('refuses providers the contract refuses', () => {
    expect(() => auctionConfigInput(AuctionType.ProviderSecondPrice)).toThrow()
    expect(() => auctionConfigInput(AuctionType.SecondPrice, [PROVIDER_A])).toThrow()
  })
})

describe('providersError', () => {
  it('accepts 1 to 4 different non-zero providers for the provider type', () => {
    for (const providers of [[PROVIDER_A], [PROVIDER_A, PROVIDER_B], [PROVIDER_A, PROVIDER_B, PROVIDER_C, PROVIDER_D]]) {
      expect(providersError(AuctionType.ProviderSecondPrice, providers)).toBeNull()
    }
  })

  it('refuses none, more than 4, the zero address, a duplicate (in any case) and a bad address', () => {
    expect(providersError(AuctionType.ProviderSecondPrice, [])).not.toBeNull()
    expect(providersError(AuctionType.ProviderSecondPrice, [PROVIDER_A, PROVIDER_B, PROVIDER_C, PROVIDER_D, PROVIDER_E])).not.toBeNull()
    expect(providersError(AuctionType.ProviderSecondPrice, [PROVIDER_A, zeroAddress])).not.toBeNull()
    expect(providersError(AuctionType.ProviderSecondPrice, [PROVIDER_A, PROVIDER_B, PROVIDER_A])).not.toBeNull()
    expect(
      providersError(AuctionType.ProviderSecondPrice, [
        '0xabcdef0000000000000000000000000000000001',
        '0xABCDEF0000000000000000000000000000000001',
      ]),
    ).not.toBeNull()
    expect(providersError(AuctionType.ProviderSecondPrice, ['0x1234' as Address])).not.toBeNull()
  })

  it('allows no provider for the other types', () => {
    for (const type of [AuctionType.FirstPrice, AuctionType.SecondPrice, AuctionType.RatioFirstPrice, AuctionType.RatioSecondPrice]) {
      expect(providersError(type, [])).toBeNull()
      expect(providersError(type, [PROVIDER_A])).not.toBeNull()
    }
  })
})

describe('encodeAuctionParams', () => {
  const abi = parseAbiParameters('uint8, uint8, uint256[16], string, address, bytes, address[]')
  const prices = [1n, 2n, 5n]

  it('round-trips the type, the prices and the providers', () => {
    const gate: Address = '0x9999999999999999999999999999999999999999'
    const encoded = encodeAuctionParams(AuctionType.ProviderSecondPrice, prices, 'Lot 4', gate, '0x1234', [PROVIDER_B, PROVIDER_A])
    const [type, levels, padded, title, decodedGate, gateConfig, providers] = decodeAbiParameters(abi, encoded)
    expect(type).toBe(4)
    expect(levels).toBe(3)
    expect(padded.slice(0, 3)).toEqual(prices)
    expect(padded.slice(3).every((price) => price === 0n)).toBe(true)
    expect(title).toBe('Lot 4')
    expect(decodedGate.toLowerCase()).toBe(gate)
    expect(gateConfig).toBe('0x1234')
    expect(providers.map((provider) => provider.toLowerCase())).toEqual([PROVIDER_B, PROVIDER_A])
  })

  it('encodes an empty provider list for the other types', () => {
    const [type, , , , gate, , providers] = decodeAbiParameters(abi, encodeAuctionParams(AuctionType.SecondPrice, prices, 'Lot'))
    expect(type).toBe(1)
    expect(gate).toBe(zeroAddress)
    expect(providers).toEqual([])
  })

  it('refuses a provider list that the contract would refuse', () => {
    expect(() => encodeAuctionParams(AuctionType.ProviderSecondPrice, prices, 'Lot')).toThrow()
    expect(() => encodeAuctionParams(AuctionType.FirstPrice, prices, 'Lot', zeroAddress, '0x', [PROVIDER_A])).toThrow()
    expect(() => encodeAuctionParams(AuctionType.ProviderSecondPrice, [2n, 1n], 'Lot', zeroAddress, '0x', [PROVIDER_A])).toThrow()
  })
})

describe('encodeMaskInput', () => {
  it('is a bid input with the provider as bidder, one ciphertext and no gate proof or signature', () => {
    const input = { provider: PROVIDER_A, ciphertext: '0xabcd', commitment: `0x${'11'.repeat(32)}`, proof: '0x99' } as const
    const abi = parseAbiParameters('address, bytes[], bytes32[], bytes, bytes, bytes')
    const [bidder, ciphertexts, commitments, proof, gateProof, signature] = decodeAbiParameters(abi, encodeMaskInput(input))
    expect(bidder.toLowerCase()).toBe(PROVIDER_A)
    expect(ciphertexts).toEqual(['0xabcd'])
    expect(commitments).toEqual([input.commitment])
    expect(proof).toBe('0x99')
    expect(gateProof).toBe('0x')
    expect(signature).toBe('0x')
    expect(encodeMaskInput(input)).toBe(
      encodeBidInput({
        bidder: PROVIDER_A,
        ciphertexts: ['0xabcd'],
        commitments: [input.commitment],
        proof: '0x99',
        gateProof: '0x',
        signature: '0x',
      }),
    )
  })
})

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
      const slot = slotIndex(n, 0, k, level)
      slots[slot] = (BigInt(test) * maskOf(slot)) % T
    }
  }
  return slots
}

describe('decodeAuction, provider-mask type', () => {
  const type = AuctionType.ProviderSecondPrice
  const decode = async (slots: bigint[], n: number) => {
    outputSlots = slots
    return decodeAuction(type, OUTPUT, n)
  }
  const invalid = { price: null, winner: null }

  beforeEach(() => {
    outputSlots = []
  })

  it.each([...ROUNDS, ...RATIO_ROUNDS])('reads the winner and the price of %j', async (bids, winner) => {
    const result = await decode(providerSlots(bids), bids.length)
    expect(result).toMatchObject({ kind: 'region', copies: 1, winner, price: expectedAuction(type, bids).price, unusedGroupsZero: true })
  })

  it('reads the same result under every non-zero mask', async () => {
    // A ramp through 1..256 and a constant 256: a non-zero test never becomes zero.
    for (const maskOf of [(slot: number) => BigInt((slot * 7) % 256) + 1n, () => T - 1n]) {
      for (const [bids, winner] of [...ROUNDS, ...RATIO_ROUNDS]) {
        expect(await decode(providerSlots(bids, maskOf), bids.length)).toMatchObject({ winner, price: expectedAuction(type, bids).price })
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
    if (result.kind !== 'region') throw new Error('region result expected')
    expect(result.set[1]).toEqual(Array.from({ length: LEVELS }, (_, level) => level < 9))
    expect(result.set[0]).toEqual(Array.from({ length: LEVELS }, (_, level) => level <= 9))
    expect(result.set[2]).toEqual(result.set[0])
  })

  describe('rejects every pattern that is not the one of a winner and a price', () => {
    const base = () => providerSlots([5, 12, 9])
    const at = (region: number, level: number) => slotIndex(3, 0, region, level)

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

describe('the no-provider type', () => {
  const type = AuctionType.QnrSecondPrice
  const decode = async (slots: bigint[], n: number) => {
    outputSlots = slots
    return decodeAuction(type, OUTPUT, n)
  }
  const invalid = { price: null, winner: null }
  /** `r = (S1^2 - 3) * (S2^2 - 3) mod t` for the share sums `S1` and `S2`. */
  const factor = (s1: bigint, s2: bigint) => (((((s1 * s1 - 3n) % T) + T) % T) * ((((s2 * s2 - 3n) % T) + T) % T)) % T

  beforeEach(() => {
    outputSlots = []
  })

  it('has 4 roles, up to 8 bidders, no providers and its own label', () => {
    expect(type).toBe(5)
    expect(Role.Share).toBe(4)
    expect(AUCTION_TYPES).toContain(type)
    expect(AUCTION_TYPE_LABELS[type]).toBe('Second-price, no providers')
    expect(rolesFor(type)).toEqual([Role.Ge, Role.Gt, Role.Share, Role.Share])
    expect(MAX_BIDDERS_BY_TYPE[type]).toBe(8)
    expect(isProviderType(type)).toBe(false)
  })

  it('gives the result of the second-price type, with up to 8 bidders', () => {
    for (const [bids] of [...ROUNDS, ...RATIO_ROUNDS]) {
      expect(expectedAuction(type, bids)).toEqual(expectedAuction(AuctionType.ProviderSecondPrice, bids))
    }
    expect(expectedAuction(type, [2, 3, 9, 1, 9, 9, 0, 9])).toEqual({ winner: 2, price: 9 })
    expect(() => expectedAuction(type, [1])).toThrow()
    expect(() => expectedAuction(type, [1, 2, 3, 4, 5, 6, 7, 8, 9])).toThrow()
  })

  it('has shares that are uniform slots in [0, t) and ignore the bid', () => {
    const first = bidSlots(Role.Share, 0)
    const second = bidSlots(Role.Share, 15)
    expect(first).toHaveLength(DEGREE)
    for (const slot of [...first, ...second]) expect(slot < T).toBe(true)
    // Two draws of 128 slots with 257 values are never equal in practice, and are not constant.
    expect([...first]).not.toEqual([...second])
    expect(new Set(first).size).toBeGreaterThan(1)
  })

  it('has a factor `(S1^2 - 3) * (S2^2 - 3)` that is never zero: 3 is not a square modulo t', () => {
    for (let s = 0n; s < T; s++) expect((s * s) % T).not.toBe(3n)
    for (let s1 = 0n; s1 < T; s1++) expect(factor(s1, (s1 * 5n + 1n) % T)).not.toBe(0n)
  })

  it.each([...ROUNDS, ...RATIO_ROUNDS])('reads the winner and the price of %j', async (bids, winner) => {
    const result = await decode(providerSlots(bids), bids.length)
    expect(result).toMatchObject({ kind: 'region', copies: 1, winner, price: expectedAuction(type, bids).price, unusedGroupsZero: true })
  })

  it('reads the same result under the factor of every pair of share sums', async () => {
    for (let shift = 0n; shift < T; shift += 16n) {
      // The sums of the slots go through every value of 0..t over the shifts.
      const maskOf = (slot: number) => factor(BigInt(slot) + shift, 2n * BigInt(slot) + shift)
      for (const [bids, winner] of [...ROUNDS, ...RATIO_ROUNDS]) {
        expect(await decode(providerSlots(bids, maskOf), bids.length)).toMatchObject({ winner, price: expectedAuction(type, bids).price })
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
    const at = (region: number, level: number) => slotIndex(3, 0, region, level)
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

  it('has no providers: the configuration, the check and the request parameters', () => {
    expect(auctionConfigInput(type)).toBe(`0x${Buffer.from('interfold-auction-config-v1').toString('hex')}05`)
    expect(() => auctionConfigInput(type, [PROVIDER_A])).toThrow()
    expect(providersError(type, [])).toBeNull()
    expect(providersError(type, [PROVIDER_A])).not.toBeNull()
    const abi = parseAbiParameters('uint8, uint8, uint256[16], string, address, bytes, address[]')
    const [encodedType, , , , , , providers] = decodeAbiParameters(abi, encodeAuctionParams(type, [1n, 2n, 5n], 'Lot'))
    expect(encodedType).toBe(5)
    expect(providers).toEqual([])
    expect(() => encodeAuctionParams(type, [1n, 2n, 5n], 'Lot', zeroAddress, '0x', [PROVIDER_A])).toThrow()
  })
})
