// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { describe, expect, it } from 'vitest'
import { zeroAddress, type Hex } from 'viem'
import { AuctionType, auctionConfigInput } from '../shared/layout'
import type { SubmittedBid } from '../shared/selection'
import { auctionInputs } from './inputs'

const alice = '0x1111111111111111111111111111111111111111'
const bob = '0x2222222222222222222222222222222222222222'

/** A bid with `roles` ciphertexts named `<name>/<role>` and commitments `0xc<role>...`. */
const bid = (bidder: `0x${string}`, name: string, version: number, firstIndex: number, roles = 3): SubmittedBid => ({
  bidder,
  version,
  firstIndex,
  ciphertexts: Array.from({ length: roles }, (_, role) => `0x${name}${role}` as Hex),
  commitments: Array.from({ length: roles }, (_, role) => `0x${name}c${role}` as Hex),
})

describe('auctionInputs', () => {
  it('puts the configuration at leaf 0 and every ciphertext of every bid at its leaf, in leaf order', () => {
    const type = AuctionType.RatioFirstPrice
    // Event order is not leaf order. Alice's update (version 2) is a published input too.
    const inputs = auctionInputs(type, [bid(bob, 'bb', 1, 4), bid(alice, 'aa', 2, 7), bid(alice, 'a1', 1, 1)])
    expect(inputs.ciphertexts).toEqual([
      [auctionConfigInput(type), 0],
      ['0xa10', 1],
      ['0xa11', 2],
      ['0xa12', 3],
      ['0xbb0', 4],
      ['0xbb1', 5],
      ['0xbb2', 6],
      ['0xaa0', 7],
      ['0xaa1', 8],
      ['0xaa2', 9],
    ])
  })

  it('sends the zero commitment, the zero address and 0 for the configuration', () => {
    const inputs = auctionInputs(AuctionType.FirstPrice, [])
    expect(inputs).toEqual({
      ciphertexts: [[auctionConfigInput(AuctionType.FirstPrice), 0]],
      commitments: [`0x${'00'.repeat(32)}`],
      slots: [zeroAddress],
      parents: [0],
    })
  })

  it('sends the commitment, the bidder and the version of each bid ciphertext', () => {
    const inputs = auctionInputs(AuctionType.FirstPrice, [bid(alice, 'a1', 1, 1), bid(bob, 'bb', 1, 4), bid(alice, 'a2', 2, 7)])
    expect(inputs.commitments.slice(1)).toEqual(['a1', 'bb', 'a2'].flatMap((name) => [0, 1, 2].map((role) => `0x${name}c${role}`)))
    expect(inputs.slots.slice(1)).toEqual([alice, alice, alice, bob, bob, bob, alice, alice, alice])
    expect(inputs.parents).toEqual([0, 1, 1, 1, 1, 1, 1, 2, 2, 2])
    for (const list of [inputs.commitments, inputs.slots, inputs.parents]) expect(list).toHaveLength(inputs.ciphertexts.length)
  })

  it('takes 4 ciphertexts per bid for the second-price ratio type, the pair mask last', () => {
    const type = AuctionType.RatioSecondPrice
    const inputs = auctionInputs(type, [bid(bob, 'bb', 1, 5, 4), bid(alice, 'aa', 1, 1, 4)])
    expect(inputs.ciphertexts.map(([, leaf]) => leaf)).toEqual([0, 1, 2, 3, 4, 5, 6, 7, 8])
    expect(inputs.ciphertexts.slice(1).map(([ciphertext]) => ciphertext)).toEqual([
      '0xaa0',
      '0xaa1',
      '0xaa2',
      '0xaa3',
      '0xbb0',
      '0xbb1',
      '0xbb2',
      '0xbb3',
    ])
  })

  it('rejects a gap in the leaves, rather than send a set whose root cannot match', () => {
    expect(() => auctionInputs(AuctionType.FirstPrice, [bid(alice, 'aa', 1, 1), bid(bob, 'bb', 1, 7)])).toThrow(/Leaf 4 has no bid event/)
    expect(() => auctionInputs(AuctionType.FirstPrice, [bid(alice, 'aa', 1, 2)])).toThrow(/Leaf 1 has no bid event/)
  })

  it('rejects a bid whose lists differ in length', () => {
    const broken = { ...bid(alice, 'aa', 1, 1), commitments: [] as Hex[] }
    expect(() => auctionInputs(AuctionType.FirstPrice, [broken])).toThrow(/3 ciphertexts and 0 commitments/)
  })
})
