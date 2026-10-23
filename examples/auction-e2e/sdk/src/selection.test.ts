// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { describe, expect, it } from 'vitest'
import type { Hex } from 'viem'
import { selectBids, type SubmittedBid } from './selection'

const alice = '0x1111111111111111111111111111111111111111'
const bob = '0x2222222222222222222222222222222222222222'

/** A ciphertext "opens" its commitment when the commitment is `c(<ciphertext>)`. */
const commitmentOf = (ciphertext: Hex): Hex => `0xc${ciphertext.slice(2)}`
const opens = (ciphertext: Hex, commitment: Hex) => commitment === commitmentOf(ciphertext)

/** Three ciphertexts per bid; the leaves of the bids follow each other from leaf 1. */
class Tree {
  private next = 1

  /** `good[r]` says whether role `r` opens its commitment. */
  bid(bidder: `0x${string}`, version: number, good: boolean[] = [true, true, true]): SubmittedBid {
    const ciphertexts = good.map((_, role) => `0x${version}${role}${bidder.slice(2, 4)}` as Hex)
    const commitments = ciphertexts.map((ciphertext, role) => (good[role] ? commitmentOf(ciphertext) : '0xdead'))
    const bid = { bidder, version, firstIndex: this.next, ciphertexts, commitments: commitments as Hex[] }
    this.next += good.length
    return bid
  }
}

const picked = (bids: SubmittedBid[]) => selectBids(bids, opens).map(({ bidder, version, position }) => [bidder, version, position])

describe('selectBids', () => {
  it('takes the latest valid version of a bidder', () => {
    const tree = new Tree()
    expect(picked([tree.bid(alice, 1), tree.bid(alice, 2), tree.bid(alice, 3)])).toEqual([[alice, 3, 0]])
  })

  it('falls back to an earlier version when the latest does not open', () => {
    const tree = new Tree()
    expect(picked([tree.bid(alice, 1), tree.bid(alice, 2, [true, false, true])])).toEqual([[alice, 1, 0]])
    expect(picked([tree.bid(alice, 1), tree.bid(alice, 2, [false, true, true]), tree.bid(alice, 3, [true, true, false])])).toEqual([
      [alice, 1, 0],
    ])
  })

  it('drops a bidder whose only bid has one bad ciphertext, whichever role it is', () => {
    for (const bad of [0, 1, 2]) {
      const tree = new Tree()
      const good = [true, true, true].map((_, role) => role !== bad)
      expect(picked([tree.bid(alice, 1, good), tree.bid(bob, 1)])).toEqual([[bob, 1, 0]])
    }
  })

  it('orders the bidders by the leaf of the chosen bid', () => {
    const tree = new Tree()
    // Alice bids first and updates last, so she counts after Bob.
    const bids = [tree.bid(alice, 1), tree.bid(bob, 1), tree.bid(alice, 2)]
    expect(picked(bids)).toEqual([
      [bob, 1, 0],
      [alice, 2, 1],
    ])
    // The order of the events does not matter.
    expect(picked([...bids].reverse())).toEqual(picked(bids))
  })

  it('treats addresses that differ only in case as one bidder', () => {
    const tree = new Tree()
    const checksummed = '0xAbCdEf0000000000000000000000000000000001'
    expect(picked([tree.bid(checksummed, 1), tree.bid(checksummed.toLowerCase() as `0x${string}`, 2)])).toHaveLength(1)
  })

  it('selects nothing when no bid opens, and skips a bid whose lists do not match', () => {
    const tree = new Tree()
    expect(picked([tree.bid(alice, 1, [false, false, false])])).toEqual([])
    const short = { ...tree.bid(alice, 1), commitments: [] as Hex[] }
    const empty = { ...tree.bid(bob, 1), ciphertexts: [] as Hex[], commitments: [] as Hex[] }
    expect(picked([short, empty])).toEqual([])
  })
})
