// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { describe, expect, it } from 'vitest'
import { stringToHex, zeroAddress, type Hex } from 'viem'
import { CONFIG_DOMAIN, saleConfigInput, saleInputs, selectBids, type SubmittedBid } from './inputs'

const alice = '0x1111111111111111111111111111111111111111'
const bob = '0x2222222222222222222222222222222222222222'

/** A bid with the ciphertext `0x<name>` and the commitment `0x<name>c`. */
const bid = (bidder: `0x${string}`, name: string, version: number, leafIndex: number): SubmittedBid => ({
  bidder,
  version,
  leafIndex,
  ciphertext: `0x${name}` as Hex,
  commitment: `0x${name}c` as Hex,
})

describe('saleConfigInput', () => {
  it('is the domain bytes and the reveal mode byte', () => {
    expect(saleConfigInput(0)).toBe(`${stringToHex(CONFIG_DOMAIN)}00`)
    expect(stringToHex(CONFIG_DOMAIN)).toBe(stringToHex('interfold-sealed-cca-config-v1'))
  })

  it('rejects a mode that is not a byte', () => {
    expect(() => saleConfigInput(256)).toThrow(/reveal mode/)
    expect(() => saleConfigInput(-1)).toThrow(/reveal mode/)
  })
})

describe('saleInputs', () => {
  it('puts the configuration at leaf 0 and the ciphertext of every bid at its leaf, in leaf order', () => {
    // Event order is not leaf order. Alice's update (version 2) is a published input too.
    const inputs = saleInputs(0, [bid(bob, 'bb', 1, 2), bid(alice, 'aa', 2, 3), bid(alice, 'a1', 1, 1)])
    expect(inputs.ciphertexts).toEqual([
      [saleConfigInput(0), 0],
      ['0xa1', 1],
      ['0xbb', 2],
      ['0xaa', 3],
    ])
    expect(inputs.commitments.slice(1)).toEqual(['0xa1c', '0xbbc', '0xaac'])
    expect(inputs.slots).toEqual([zeroAddress, alice, bob, alice])
    expect(inputs.parents).toEqual([0, 1, 1, 2])
  })

  it('sends the zero commitment, the zero address and 0 for the configuration', () => {
    expect(saleInputs(0, [])).toEqual({
      ciphertexts: [[saleConfigInput(0), 0]],
      commitments: [`0x${'00'.repeat(32)}`],
      slots: [zeroAddress],
      parents: [0],
    })
  })

  it('refuses a round with a missing bid event', () => {
    expect(() => saleInputs(0, [bid(alice, 'aa', 1, 1), bid(bob, 'bb', 1, 3)])).toThrow(/Leaf 2 has no bid event/)
    expect(() => saleInputs(0, [bid(alice, 'aa', 1, 2)])).toThrow(/Leaf 1 has no bid event/)
  })
})

describe('selectBids', () => {
  const opensAll = () => true

  it('takes the latest version of each bidder, in leaf order', () => {
    const bids = [bid(alice, 'a1', 1, 1), bid(bob, 'bb', 1, 2), bid(alice, 'a2', 2, 3)]
    expect(selectBids(bids, opensAll).map((selected) => selected.ciphertext)).toEqual(['0xbb', '0xa2'])
  })

  it('falls back to an earlier version when the latest does not open its commitment', () => {
    const bids = [bid(alice, 'a1', 1, 1), bid(alice, 'a2', 2, 2), bid(alice, 'a3', 3, 3)]
    const opens = (ciphertext: Hex) => ciphertext !== '0xa3'
    expect(selectBids(bids, opens).map((selected) => selected.ciphertext)).toEqual(['0xa2'])
  })

  it('drops a bidder that has no bid that opens', () => {
    const bids = [bid(alice, 'a1', 1, 1), bid(bob, 'bb', 1, 2)]
    expect(selectBids(bids, (ciphertext) => ciphertext === '0xbb').map((selected) => selected.bidder)).toEqual([bob])
    expect(selectBids(bids, () => false)).toEqual([])
  })

  it('compares bidder addresses without regard to case', () => {
    const upper = alice.toUpperCase().replace('0X', '0x') as `0x${string}`
    expect(selectBids([bid(alice, 'a1', 1, 1), bid(upper, 'a2', 2, 2)], opensAll)).toHaveLength(1)
  })
})
