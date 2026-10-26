// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { decodeAbiParameters, hashTypedData, keccak256, parseAbiParameters, recoverTypedDataAddress } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { describe, expect, it } from 'vitest'
import {
  bidInputsHash,
  bidTypedData,
  encodeBidInput,
  encodeClaimData,
  encodeLinkParams,
  encodeSaleParams,
  linearPrices,
  priceListError,
  readPriceList,
  readTierList,
  tierListError,
} from './sale'

const TOKEN = '0x1111111111111111111111111111111111111111'
const PAY = '0x2222222222222222222222222222222222222222'
const word = (byte: number) => `0x${byte.toString(16).padStart(2, '0').repeat(32)}` as const

describe('price list and tiers', () => {
  it('checks the rules of the contract', () => {
    expect(priceListError(linearPrices(1_000_000n, 5_000_000n, 8))).toBeNull()
    expect(priceListError(linearPrices(1n, 3n, 8))).toMatch('must increase')
    expect(priceListError([1n, 2n, 3n])).toMatch('8 to 16')
    expect(priceListError(Array.from({ length: 17 }, (_, i) => BigInt(i + 1)))).toMatch('8 to 16')
    expect(priceListError([0n, ...Array.from({ length: 7 }, (_, i) => BigInt(i + 1))])).toMatch('from 1')
    expect(tierListError([10, 100, 1000])).toBeNull()
    expect(tierListError([])).toMatch('1 to 4')
    expect(tierListError([10, 10])).toMatch('must increase')
    expect(tierListError([4096])).toMatch('from 1 to 4095')
  })
  it('reads the padded getter values', () => {
    const prices = [...linearPrices(10n, 80n, 8), ...Array(8).fill(0n)]
    expect(readPriceList(8, prices)).toEqual(linearPrices(10n, 80n, 8))
    expect(readTierList([5, 50, 0, 0])).toEqual([5, 50])
  })
})

describe('requests', () => {
  it('encodes the role-1 params as the contract decodes them', () => {
    const prices = linearPrices(1_000_000n, 8_000_000n, 8)
    const data = encodeSaleParams({
      prices,
      saleToken: TOKEN,
      supply: 10n ** 20n,
      paymentToken: PAY,
      budgetUnit: 1_000_000n,
      tiers: [10, 100],
      title: 'Demo',
    })
    const [role, body] = decodeAbiParameters(parseAbiParameters('uint8, bytes'), data)
    expect(role).toBe(1)
    const [levels, padded, saleToken, supply, paymentToken, unit, tiers, title] = decodeAbiParameters(
      parseAbiParameters('uint8, uint256[16], address, uint256, address, uint256, uint16[4], string'),
      body,
    )
    expect(levels).toBe(8)
    expect(padded.slice(0, 8)).toEqual(prices)
    expect(padded.slice(8)).toEqual(Array(8).fill(0n))
    expect([saleToken, supply, paymentToken, unit, title]).toEqual([TOKEN, 10n ** 20n, PAY, 1_000_000n, 'Demo'])
    expect(tiers).toEqual([10, 100, 0, 0])
  })
  it('refuses params that the contract would refuse', () => {
    const base = {
      prices: linearPrices(1_000_000n, 8_000_000n, 8),
      saleToken: TOKEN,
      supply: 1n,
      paymentToken: PAY,
      budgetUnit: 1n,
      tiers: [1],
      title: 'x',
    } as const
    expect(() => encodeSaleParams({ ...base, supply: 0n })).toThrow('supply')
    expect(() => encodeSaleParams({ ...base, budgetUnit: 0n })).toThrow('budget unit')
    expect(() => encodeSaleParams({ ...base, title: '' })).toThrow('title')
    expect(() => encodeSaleParams({ ...base, tiers: [5000] })).toThrow('tier')
    expect(() => encodeSaleParams({ ...base, prices: [1n, 2n] })).toThrow('prices')
  })
  it('encodes the role-2 params', () => {
    const [role, body] = decodeAbiParameters(parseAbiParameters('uint8, bytes'), encodeLinkParams(42n))
    expect(role).toBe(2)
    expect(decodeAbiParameters(parseAbiParameters('uint256'), body)).toEqual([42n])
  })
})

describe('bids and claims', () => {
  const bid = {
    bidder: TOKEN,
    tier: 1,
    ciphertext1: '0x0102',
    ciphertext2: '0x0304',
    ctCommitment1: word(1),
    ctCommitment2: word(2),
    bidCommitment: word(3),
    proof: '0x01',
  } as const
  it('round-trips a bid', () => {
    const [decoded] = decodeAbiParameters(
      parseAbiParameters(
        '(address bidder, uint8 tier, bytes ciphertext1, bytes ciphertext2, bytes32 ctCommitment1, bytes32 ctCommitment2, bytes32 bidCommitment, bytes proof, bytes signature, uint256 permitDeadline, uint8 v, bytes32 r, bytes32 s)',
      ),
      encodeBidInput({ ...bid, signature: '0xabcd', permit: { deadline: 99n, v: 27, r: word(7), s: word(8) } }),
    )
    expect(decoded).toMatchObject({
      bidder: TOKEN,
      tier: 1,
      ciphertext1: '0x0102',
      signature: '0xabcd',
      permitDeadline: 99n,
      v: 27,
      r: word(7),
      s: word(8),
    })
    const [direct] = decodeAbiParameters(
      parseAbiParameters(
        '(address bidder, uint8 tier, bytes ciphertext1, bytes ciphertext2, bytes32 ctCommitment1, bytes32 ctCommitment2, bytes32 bidCommitment, bytes proof, bytes signature, uint256 permitDeadline, uint8 v, bytes32 r, bytes32 s)',
      ),
      encodeBidInput(bid),
    )
    expect(direct.signature).toBe('0x')
  })
  it('signs the inputs hash: the relayer cannot swap a ciphertext', async () => {
    const account = privateKeyToAccount(word(9))
    const hash = bidInputsHash(word(1), word(2), word(3), '0x0102', '0x0304')
    expect(hash).not.toBe(bidInputsHash(word(1), word(2), word(3), '0x0102', '0x0305'))
    const typed = bidTypedData(31337, TOKEN, 7n, account.address, 1, hash)
    const signature = await account.signTypedData(typed)
    expect(await recoverTypedDataAddress({ ...typed, signature })).toBe(account.address)
    expect(hashTypedData(typed)).toMatch(/^0x[0-9a-f]{64}$/)
    expect(keccak256('0x')).toBeTruthy()
  })
  it('round-trips claim data', () => {
    const data = { proof: '0x01', nullifier: word(5), recipient: PAY, escrowUnits: 100, budgetUnits: 37, cmp: 1, indexPlusOne: 4 } as const
    const [decoded] = decodeAbiParameters(
      parseAbiParameters(
        '(bytes proof, bytes32 nullifier, address recipient, uint16 escrowUnits, uint16 budgetUnits, uint8 cmp, uint8 indexPlusOne)',
      ),
      encodeClaimData(data),
    )
    expect(decoded).toEqual(data)
  })
})
