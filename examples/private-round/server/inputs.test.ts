// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { describe, expect, it } from 'vitest'
import { zeroAddress, type Hex } from 'viem'
import { roundConfigInput } from '@interfold/private-round'
import { roundInputs, selectBids, type SubmittedBid } from './inputs'

const alice = '0x1111111111111111111111111111111111111111'
const bob = '0x2222222222222222222222222222222222222222'

const params = { levels: 8, reserveStep: 2, lots: 2, minLots: 1 }

/** A bid with the ciphertexts `0x<name>00` (bid) and `0x<name>01` (mask) and the commitments `0x<name>c0`, `0x<name>c1`. */
const bid = (bidder: `0x${string}`, name: string, version: number, firstLeaf: number): SubmittedBid => ({
  bidder,
  version,
  firstLeaf,
  ciphertexts: [`0x${name}00`, `0x${name}01`] as Hex[],
  ctCommitments: [`0x${name}c0`, `0x${name}c1`] as Hex[],
})

describe('roundInputs', () => {
  it('puts the configuration at leaf 0 and both ciphertexts of every bid at their leaves, in leaf order', () => {
    // Event order is not leaf order. Alice's update (version 2) is a published input too.
    const inputs = roundInputs(params, [bid(bob, 'bb', 1, 3), bid(alice, 'aa', 2, 5), bid(alice, 'a1', 1, 1)])
    expect(inputs.ciphertexts).toEqual([
      [roundConfigInput(params), 0],
      ['0xa100', 1],
      ['0xa101', 2],
      ['0xbb00', 3],
      ['0xbb01', 4],
      ['0xaa00', 5],
      ['0xaa01', 6],
    ])
    expect(inputs.commitments.slice(1)).toEqual(['0xa1c0', '0xa1c1', '0xbbc0', '0xbbc1', '0xaac0', '0xaac1'])
    expect(inputs.slots).toEqual([zeroAddress, alice, alice, bob, bob, alice, alice])
    // The two ciphertexts of a bid carry the same bidder and the same version: one run of equal metadata.
    expect(inputs.parents).toEqual([0, 1, 1, 1, 1, 2, 2])
  })

  it('builds the configuration from the public parameters', () => {
    expect(roundInputs(params, [])).toEqual({
      ciphertexts: [[roundConfigInput(params), 0]],
      commitments: [`0x${'00'.repeat(32)}`],
      slots: [zeroAddress],
      parents: [0],
    })
    expect(roundInputs({ ...params, minLots: 2 }, []).ciphertexts[0][0]).not.toBe(roundConfigInput(params))
  })

  it('refuses parameters that the program would not accept', () => {
    expect(() => roundInputs({ ...params, lots: 13 }, [])).toThrow(/lots/)
    expect(() => roundInputs({ ...params, reserveStep: 8 }, [])).toThrow(/reserve/)
  })

  it('refuses a round with a missing bid event', () => {
    expect(() => roundInputs(params, [bid(alice, 'aa', 1, 1), bid(bob, 'bb', 1, 5)])).toThrow(/Leaf 3 has no bid event/)
    expect(() => roundInputs(params, [bid(alice, 'aa', 1, 2)])).toThrow(/Leaf 1 has no bid event/)
  })

  it('refuses a bid with a number of ciphertexts that is not two', () => {
    const odd: SubmittedBid = { ...bid(alice, 'aa', 1, 1), ciphertexts: ['0xaa00'], ctCommitments: ['0xaac0'] }
    expect(() => roundInputs(params, [odd])).toThrow(/a bid has 2/)
  })
})

describe('selectBids', () => {
  const opensAll = () => true
  const names = (bids: SubmittedBid[]) => bids.map((selected) => selected.ciphertexts[0])

  it('takes the latest version of each bidder, in leaf order', () => {
    const bids = [bid(alice, 'a1', 1, 1), bid(bob, 'bb', 1, 3), bid(alice, 'a2', 2, 5)]
    expect(names(selectBids(bids, opensAll))).toEqual(['0xbb00', '0xa200'])
  })

  it('falls back to an earlier version when the latest does not open its commitments', () => {
    const bids = [bid(alice, 'a1', 1, 1), bid(alice, 'a2', 2, 3), bid(alice, 'a3', 3, 5)]
    const opens = (ciphertext: Hex) => !ciphertext.startsWith('0xa3')
    expect(names(selectBids(bids, opens))).toEqual(['0xa200'])
  })

  it('drops a whole bid when only one of its two ciphertexts opens its commitment', () => {
    const bids = [bid(alice, 'a1', 1, 1), bid(alice, 'a2', 2, 3)]
    // The mask of version 2 does not open: the run is not taken, even though its bid ciphertext opens.
    expect(names(selectBids(bids, (ciphertext) => ciphertext !== '0xa201'))).toEqual(['0xa100'])
    // The bid ciphertext of version 2 does not open, the mask does.
    expect(names(selectBids(bids, (ciphertext) => ciphertext !== '0xa200'))).toEqual(['0xa100'])
  })

  it('drops a bidder that has no bid that opens', () => {
    const bids = [bid(alice, 'a1', 1, 1), bid(bob, 'bb', 1, 3)]
    expect(selectBids(bids, (ciphertext) => ciphertext.startsWith('0xbb')).map((selected) => selected.bidder)).toEqual([bob])
    expect(selectBids(bids, () => false)).toEqual([])
  })

  it('compares bidder addresses without regard to case', () => {
    const upper = alice.toUpperCase().replace('0X', '0x') as `0x${string}`
    expect(selectBids([bid(alice, 'a1', 1, 1), bid(upper, 'a2', 2, 3)], opensAll)).toHaveLength(1)
  })

  it('does not take a bid with a wrong number of ciphertexts', () => {
    const odd: SubmittedBid = { ...bid(alice, 'aa', 1, 1), ciphertexts: ['0xaa00'], ctCommitments: ['0xaac0'] }
    expect(selectBids([odd], opensAll)).toEqual([])
  })
})
