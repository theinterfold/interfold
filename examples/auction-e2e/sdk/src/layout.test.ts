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
  Role,
  auctionConfigInput,
  decodeAuction,
  encodeAuctionParams,
  encodeBidInput,
  encodeMaskInput,
  expectedAuction,
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

describe('expectedAuction', () => {
  it.each(ROUNDS)('picks the earliest position of a tie at the top: %j', (bids, winner) => {
    for (const type of AUCTION_TYPES) {
      expect(expectedAuction(type, bids).winner).toBe(winner)
    }
  })

  it('prices a tie at the top at the tied bid, and a unique top by its type', () => {
    expect(expectedAuction(AuctionType.QnrSecondPrice, [7, 3, 7])).toEqual({ winner: 0, price: 7 })
    expect(expectedAuction(AuctionType.FirstPrice, [7, 3, 7])).toEqual({ winner: 0, price: 7 })
    expect(expectedAuction(AuctionType.QnrSecondPrice, [5, 12, 9])).toEqual({ winner: 1, price: 9 })
    expect(expectedAuction(AuctionType.FirstPrice, [5, 12, 9])).toEqual({ winner: 1, price: 12 })
  })
})

describe('the first-price type', () => {
  const type = AuctionType.FirstPrice
  const decode = async (slots: bigint[], n: number) => {
    outputSlots = slots
    return decodeAuction(type, OUTPUT, n)
  }
  const invalid = { price: null, winner: null }

  beforeEach(() => {
    outputSlots = []
  })

  it('has 3 roles, up to 8 bidders, no providers and its own label', () => {
    expect(type).toBe(0)
    expect(Role.Mask).toBe(2)
    expect(AUCTION_TYPES).toContain(type)
    expect(AUCTION_TYPE_LABELS[type]).toBe('First-price')
    expect(rolesFor(type)).toEqual([Role.Ge, Role.Gt, Role.Mask])
    expect(MAX_BIDDERS_BY_TYPE[type]).toBe(8)
    expect(isProviderType(type)).toBe(false)
  })

  it.each(ROUNDS)('reads the earliest tied bidder as the winner, and the highest bid as the price: %j', async (bids, winner) => {
    const result = await decode(firstPriceSlots(bids), bids.length)
    expect(result).toMatchObject({ winner, price: expectedAuction(type, bids).price, unusedGroupsZero: true })
  })

  it('reads the same result under every mask, also a mask that is zero in every slot', async () => {
    const masks = [() => 0n, (slot: number) => BigInt((slot * 7) % PLAINTEXT_MODULUS), () => T - 1n, () => 1n]
    for (const maskOf of masks) {
      for (const [bids, winner] of ROUNDS) {
        expect(await decode(firstPriceSlots(bids, maskOf), bids.length)).toMatchObject({ winner, price: expectedAuction(type, bids).price })
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

  it('has no providers: the configuration, the check and the request parameters', () => {
    expect(() => auctionConfigInput(type, [PROVIDER_A])).toThrow()
    expect(providersError(type, [])).toBeNull()
    expect(providersError(type, [PROVIDER_A])).not.toBeNull()
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
    expect(type).toBe(1)
    expect(AUCTION_TYPES).toContain(type)
    expect(AUCTION_TYPE_LABELS[type]).toBe('Second-price, mask providers')
    expect(rolesFor(type)).toEqual([Role.Ge, Role.Gt])
    expect(MAX_BIDDERS_BY_TYPE[type]).toBe(8)
    expect(isProviderType(type)).toBe(true)
    for (const other of [AuctionType.FirstPrice, AuctionType.QnrSecondPrice]) {
      expect(isProviderType(other)).toBe(false)
    }
    expect(MAX_PROVIDERS).toBe(4)
    expect(MASK_VERSION).toBe(0xffffffff)
  })

  it('gives the second-highest bid as the price, with up to 8 bidders', () => {
    expect(expectedAuction(AuctionType.ProviderSecondPrice, [5, 12, 9])).toEqual({ winner: 1, price: 9 })
    expect(expectedAuction(AuctionType.ProviderSecondPrice, [7, 3, 7])).toEqual({ winner: 0, price: 7 })
    expect(expectedAuction(AuctionType.ProviderSecondPrice, [2, 3, 9, 1, 9, 9, 0, 9])).toEqual({ winner: 2, price: 9 })
    expect(() => expectedAuction(AuctionType.ProviderSecondPrice, [1])).toThrow()
    expect(() => expectedAuction(AuctionType.ProviderSecondPrice, [1, 2, 3, 4, 5, 6, 7, 8, 9])).toThrow()
  })
})

describe('auctionConfigInput', () => {
  it('has no providers for the types 0 and 2: the domain and the type byte', () => {
    for (const type of [AuctionType.FirstPrice, AuctionType.QnrSecondPrice]) {
      expect(auctionConfigInput(type)).toBe(`0x${Buffer.from('interfold-auction-config-v1').toString('hex')}0${type}`)
    }
    expect(keccak256(auctionConfigInput(AuctionType.QnrSecondPrice))).toBe(
      keccak256(`0x${Buffer.from('interfold-auction-config-v1\x02').toString('hex')}`),
    )
  })

  it('matches the vector of AuctionProgram.configInput for 2 providers: 20 raw bytes each', () => {
    const input = auctionConfigInput(AuctionType.ProviderSecondPrice, [PROVIDER_A, PROVIDER_B])
    expect(input).toBe(
      '0x696e746572666f6c642d61756374696f6e2d636f6e6669672d76310111111111111111111111111111111111111111112222222222222222222222222222222222222222',
    )
    expect((input.length - 2) / 2).toBe(68)
    expect(keccak256(input)).toBe('0xc35ec886d8a9aa1b8ee8253c137ea4da5393c43cd7a1e2cd1e7adf4e08af0746')
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
    expect(() => auctionConfigInput(AuctionType.FirstPrice, [PROVIDER_A])).toThrow()
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
    for (const type of [AuctionType.FirstPrice, AuctionType.QnrSecondPrice]) {
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
    expect(type).toBe(1)
    expect(levels).toBe(3)
    expect(padded.slice(0, 3)).toEqual(prices)
    expect(padded.slice(3).every((price) => price === 0n)).toBe(true)
    expect(title).toBe('Lot 4')
    expect(decodedGate.toLowerCase()).toBe(gate)
    expect(gateConfig).toBe('0x1234')
    expect(providers.map((provider) => provider.toLowerCase())).toEqual([PROVIDER_B, PROVIDER_A])
  })

  it('encodes an empty provider list for the other types', () => {
    const [type, , , , gate, , providers] = decodeAbiParameters(abi, encodeAuctionParams(AuctionType.FirstPrice, prices, 'Lot'))
    expect(type).toBe(0)
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
      const slot = slotIndex(k, level)
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

  it.each(ROUNDS)('reads the winner and the price of %j', async (bids, winner) => {
    const result = await decode(providerSlots(bids), bids.length)
    expect(result).toMatchObject({ winner, price: expectedAuction(type, bids).price, unusedGroupsZero: true })
  })

  it('reads the same result under every non-zero mask', async () => {
    // A ramp through 1..256 and a constant 256: a non-zero test never becomes zero.
    for (const maskOf of [(slot: number) => BigInt((slot * 7) % 256) + 1n, () => T - 1n]) {
      for (const [bids, winner] of ROUNDS) {
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
    expect(type).toBe(2)
    expect(Role.Share).toBe(3)
    expect(AUCTION_TYPES).toContain(type)
    expect(AUCTION_TYPE_LABELS[type]).toBe('Second-price, no providers')
    expect(rolesFor(type)).toEqual([Role.Ge, Role.Gt, Role.Share, Role.Share])
    expect(MAX_BIDDERS_BY_TYPE[type]).toBe(8)
    expect(isProviderType(type)).toBe(false)
  })

  it('gives the result of the second-price type, with up to 8 bidders', () => {
    for (const [bids] of ROUNDS) {
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

  it.each(ROUNDS)('reads the winner and the price of %j', async (bids, winner) => {
    const result = await decode(providerSlots(bids), bids.length)
    expect(result).toMatchObject({ winner, price: expectedAuction(type, bids).price, unusedGroupsZero: true })
  })

  it('reads the same result under the factor of every pair of share sums', async () => {
    for (let shift = 0n; shift < T; shift += 16n) {
      // The sums of the slots go through every value of 0..t over the shifts.
      const maskOf = (slot: number) => factor(BigInt(slot) + shift, 2n * BigInt(slot) + shift)
      for (const [bids, winner] of ROUNDS) {
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

  it('has no providers: the configuration, the check and the request parameters', () => {
    expect(auctionConfigInput(type)).toBe(`0x${Buffer.from('interfold-auction-config-v1').toString('hex')}02`)
    expect(() => auctionConfigInput(type, [PROVIDER_A])).toThrow()
    expect(providersError(type, [])).toBeNull()
    expect(providersError(type, [PROVIDER_A])).not.toBeNull()
    const abi = parseAbiParameters('uint8, uint8, uint256[16], string, address, bytes, address[]')
    const [encodedType, , , , , , providers] = decodeAbiParameters(abi, encodeAuctionParams(type, [1n, 2n, 5n], 'Lot'))
    expect(encodedType).toBe(2)
    expect(providers).toEqual([])
    expect(() => encodeAuctionParams(type, [1n, 2n, 5n], 'Lot', zeroAddress, '0x', [PROVIDER_A])).toThrow()
  })
})
