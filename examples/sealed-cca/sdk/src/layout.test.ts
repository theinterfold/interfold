// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { existsSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { decodePlaintextSlots } from '@interfold/sdk'
import { decodeAbiParameters, hashTypedData, type Hex, parseAbiParameters, recoverTypedDataAddress, zeroAddress } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { describe, expect, it } from 'vitest'
import {
  assertBid,
  bidInputsHash,
  bidSlots,
  bidTypedData,
  decodeOutput,
  DEGREE,
  encodeBidInput,
  encodeClaimData,
  encodeSaleParams,
  evenPrices,
  expectedOutput,
  LEVELS,
  linearPrices,
  MAX_BIDDERS,
  MAX_BIDS_PER_BIDDER,
  PRESET,
  outputSlots,
  priceListError,
  readOutputSlots,
  readPriceList,
} from './layout'

describe('bid slots', () => {
  it('has the thermometer in the first 16 slots and the version in the bidder slot', () => {
    const slots = bidSlots(5, 3, 2)
    expect(slots).toHaveLength(DEGREE)
    for (let l = 0; l < LEVELS; l++) expect(slots[l]).toBe(l <= 5 ? 1n : 0n)
    expect(slots[LEVELS + 3]).toBe(2n)
    const nonZero = [...slots].filter((slot) => slot !== 0n).length
    expect(nonZero).toBe(6 + 1)
  })

  it('covers the extreme bids and the last bidder', () => {
    expect([...bidSlots(0, 0, 1)].filter((slot) => slot !== 0n)).toHaveLength(2)
    const last = bidSlots(LEVELS - 1, MAX_BIDDERS - 1, 3)
    expect(last[DEGREE - 1]).toBe(3n)
    expect([...last.slice(0, LEVELS)].every((slot) => slot === 1n)).toBe(true)
  })

  it('rejects a bid, an index or a version out of range', () => {
    expect(() => bidSlots(16, 0, 1)).toThrow()
    expect(() => bidSlots(-1, 0, 1)).toThrow()
    expect(() => bidSlots(0, MAX_BIDDERS, 1)).toThrow()
    expect(() => bidSlots(0, 0, 0)).toThrow()
    expect(() => bidSlots(0, 0, 4)).toThrow()
    expect(() => assertBid(1.5)).toThrow()
  })
})

describe('output slots', () => {
  it('is the sum of the selected bids', () => {
    const output = expectedOutput([
      { level: 5, bidderIndex: 0, version: 1 },
      { level: 2, bidderIndex: 1, version: 3 },
      { level: 9, bidderIndex: 4, version: 2 },
    ])
    expect(output.counts.map(Number)).toEqual([3, 3, 3, 2, 2, 2, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0])
    expect(output.counted.slice(0, 5)).toEqual([1, 3, 0, 0, 2])
    expect(output.counted).toHaveLength(MAX_BIDDERS)
  })

  it('reads and writes the same slots', () => {
    const output = expectedOutput([{ level: 15, bidderIndex: 111, version: 3 }])
    expect(readOutputSlots(outputSlots(output))).toEqual(output)
  })

  it('rejects a counted version above 3', () => {
    const slots = new Array<bigint>(DEGREE).fill(0n)
    slots[20] = 4n
    expect(() => readOutputSlots(slots)).toThrow()
  })
})

describe('prices', () => {
  it('accepts a strictly increasing list', () => {
    expect(priceListError(evenPrices(1n, 1n, 16))).toBeNull()
    expect(priceListError(linearPrices(1_000_000n, 2_500_000n, 16))).toBeNull()
  })

  it('rejects an invalid list', () => {
    expect(priceListError([1n])).not.toBeNull()
    expect(priceListError(Array.from({ length: 17 }, (_, i) => BigInt(i + 1)))).not.toBeNull()
    expect(priceListError([2n, 2n])).not.toBeNull()
    expect(priceListError([3n, 2n])).not.toBeNull()
    expect(priceListError([0n, 1n])).not.toBeNull()
    // Rounding makes two steps equal.
    expect(priceListError(linearPrices(1n, 3n, 8))).not.toBeNull()
  })

  it('goes from the floor to the cap', () => {
    const prices = linearPrices(100n, 400n, 4)
    expect(prices).toEqual([100n, 200n, 300n, 400n])
  })

  it('reads the first `levels` prices of the padded list', () => {
    const padded = [...evenPrices(1n, 1n, 4), ...new Array<bigint>(12).fill(0n)]
    expect(readPriceList(4, padded)).toEqual([1n, 2n, 3n, 4n])
    expect(() => readPriceList(1, padded)).toThrow()
  })
})

describe('encoders', () => {
  const saleToken = '0x5FbDB2315678afecb367f032d93F642f64180aa3'
  const paymentToken = '0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512'

  it('encodes the sale parameters', () => {
    const prices = evenPrices(10n, 5n, 4)
    const data = encodeSaleParams({ prices, saleToken, supply: 1000n, paymentToken, escrow: 50n, title: 'A sale' })
    const [mode, levels, padded, token, supply, payment, escrow, title, gate, gateConfig] = decodeAbiParameters(
      parseAbiParameters('uint8, uint8, uint256[16], address, uint256, address, uint256, string, address, bytes'),
      data,
    )
    expect([mode, levels]).toEqual([0, 4])
    expect(padded.slice(0, 4)).toEqual(prices)
    expect(padded.slice(4).every((price) => price === 0n)).toBe(true)
    expect(token).toBe(saleToken)
    expect(supply).toBe(1000n)
    expect(payment).toBe(paymentToken)
    expect(escrow).toBe(50n)
    expect(title).toBe('A sale')
    expect(gate).toBe(zeroAddress)
    expect(gateConfig).toBe('0x')
  })

  it('rejects an invalid sale', () => {
    expect(() => encodeSaleParams({ prices: [2n, 1n], saleToken, supply: 1n, paymentToken, escrow: 1n, title: '' })).toThrow()
    expect(() => encodeSaleParams({ prices: [1n, 2n], saleToken, supply: 0n, paymentToken, escrow: 1n, title: '' })).toThrow()
    expect(() => encodeSaleParams({ prices: [1n, 2n], saleToken, supply: 1n, paymentToken, escrow: 0n, title: '' })).toThrow()
  })

  it('encodes the bid input and the claim data', () => {
    const bidder = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8'
    const data = encodeBidInput({
      bidder,
      ciphertext: '0x1234',
      ctCommitment: `0x${'11'.repeat(32)}`,
      bidCommitment: `0x${'22'.repeat(32)}`,
      proof: '0xabcd',
      gateProof: '0x',
      signature: '0x',
    })
    const decoded = decodeAbiParameters(parseAbiParameters('address, bytes, bytes32, bytes32, bytes, bytes, bytes'), data)
    expect(decoded[0]).toBe(bidder)
    expect(decoded[1]).toBe('0x1234')
    expect(decoded[3]).toBe(`0x${'22'.repeat(32)}`)
    expect(decodeAbiParameters(parseAbiParameters('uint8, bytes'), encodeClaimData(2, '0xbeef'))).toEqual([2, '0xbeef'])
  })

  it('signs a bid that recovers to the bidder', async () => {
    const account = privateKeyToAccount('0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d')
    const program = '0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9'
    const inputsHash = bidInputsHash(`0x${'11'.repeat(32)}`, `0x${'22'.repeat(32)}`, '0x1234')
    const typed = bidTypedData(31337, program, 7n, account.address, 2, inputsHash)
    const signature = await account.signTypedData(typed)
    expect(await recoverTypedDataAddress({ ...typed, signature })).toBe(account.address)
    expect(hashTypedData(typed)).toMatch(/^0x[0-9a-f]{64}$/)
    expect(typed.domain.name).toBe('SealedCcaProgram')
  })
})

const slotVectorsPath = join(dirname(fileURLToPath(import.meta.url)), '../test-vectors/slots.json')

describe.skipIf(!existsSync(slotVectorsPath))('output decoder against the shared slot vectors', () => {
  const { cases } = (existsSync(slotVectorsPath) ? JSON.parse(readFileSync(slotVectorsPath, 'utf8')) : { cases: [] }) as {
    cases: { name: string; plaintext: Hex; slots: (string | number)[] }[]
  }

  it('has cases', () => {
    expect(cases.length).toBeGreaterThan(0)
  })

  it.each(cases.map((vector) => [vector.name, vector] as const))('decodes %s like the contract', async (_name, vector) => {
    const slots = vector.slots.map(BigInt)
    expect(await decodePlaintextSlots(vector.plaintext, PRESET)).toEqual(slots)
    // The vectors hold arbitrary slot values; `decodeOutput` accepts the ones a sale can produce.
    if (slots.slice(LEVELS).every((slot) => slot <= BigInt(MAX_BIDS_PER_BIDDER))) {
      expect(outputSlots(await decodeOutput(vector.plaintext))).toEqual(slots)
    } else {
      await expect(decodeOutput(vector.plaintext)).rejects.toThrow()
    }
  })
})
