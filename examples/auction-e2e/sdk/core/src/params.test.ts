// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { describe, expect, it } from 'vitest'
import { decodeAbiParameters, keccak256, parseAbiParameters, zeroAddress, type Address } from 'viem'
import {
  AuctionType,
  Role,
  DEGREE,
  PLAINTEXT_MODULUS,
  auctionConfigInput,
  bidSlots,
  encodeAuctionParams,
  evenPrices,
  priceListError,
  providersError,
  readPriceList,
} from './index'

const T = BigInt(PLAINTEXT_MODULUS)

/** The first two addresses of the config vector that `AuctionProgram.configInput` and the program also assert. */
const PROVIDER_A: Address = '0x1111111111111111111111111111111111111111'
const PROVIDER_B: Address = '0x2222222222222222222222222222222222222222'
const PROVIDER_C: Address = '0x3333333333333333333333333333333333333333'
const PROVIDER_D: Address = '0x4444444444444444444444444444444444444444'
const PROVIDER_E: Address = '0x5555555555555555555555555555555555555555'

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

describe('priceListError', () => {
  it('accepts 2 to 16 strictly increasing prices', () => {
    expect(priceListError([1n, 2n])).toBeNull()
    expect(priceListError(evenPrices(10n, 5n, 16))).toBeNull()
  })

  it('refuses a list that is too short, too long, flat, decreasing or out of range', () => {
    expect(priceListError([1n])).not.toBeNull()
    expect(priceListError(evenPrices(1n, 1n, 17))).not.toBeNull()
    expect(priceListError([1n, 1n])).not.toBeNull()
    expect(priceListError([3n, 2n])).not.toBeNull()
    expect(priceListError([-1n, 2n])).not.toBeNull()
    expect(priceListError([1n, 2n ** 256n])).not.toBeNull()
  })
})

describe('readPriceList', () => {
  it('reads the first `levels` prices of the padded list', () => {
    expect(readPriceList(3n, [1n, 2n, 5n, 0n, 0n])).toEqual([1n, 2n, 5n])
    expect(() => readPriceList(1, [1n, 2n])).toThrow()
    expect(() => readPriceList(17, [])).toThrow()
  })
})

describe('bidSlots', () => {
  it('has thermometer slots: ge is [b >= level] and gt is [b > level]', () => {
    const ge = bidSlots(Role.Ge, 3)
    const gt = bidSlots(Role.Gt, 3)
    expect([...ge.slice(0, 6)]).toEqual([1n, 1n, 1n, 1n, 0n, 0n])
    expect([...gt.slice(0, 6)]).toEqual([1n, 1n, 1n, 0n, 0n, 0n])
    expect(ge[16 + 3]).toBe(1n)
  })

  it('refuses a bid outside 0 to 15 for a thermometer', () => {
    expect(() => bidSlots(Role.Ge, 16)).toThrow()
    expect(() => bidSlots(Role.Gt, -1)).toThrow()
    expect(() => bidSlots(Role.Ge, 1.5)).toThrow()
  })

  it('has masks and shares that are uniform slots in [0, t) and ignore the bid', () => {
    for (const role of [Role.Mask, Role.Share]) {
      const first = bidSlots(role, 0)
      const second = bidSlots(role, 15)
      expect(first).toHaveLength(DEGREE)
      for (const slot of [...first, ...second]) expect(slot < T).toBe(true)
      // Two draws of 128 slots with 257 values are never equal in practice, and are not constant.
      expect([...first]).not.toEqual([...second])
      expect(new Set(first).size).toBeGreaterThan(1)
    }
  })
})

describe('providers of the types without mask providers', () => {
  it('are refused by the configuration input, the check and the request parameters', () => {
    for (const type of [AuctionType.FirstPrice, AuctionType.QnrSecondPrice]) {
      expect(() => auctionConfigInput(type, [PROVIDER_A])).toThrow()
      expect(providersError(type, [])).toBeNull()
      expect(providersError(type, [PROVIDER_A])).not.toBeNull()
      expect(() => encodeAuctionParams(type, [1n, 2n, 5n], 'Lot', zeroAddress, '0x', [PROVIDER_A])).toThrow()
    }
  })
})
