// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { describe, expect, it } from 'vitest'
import type { Hex } from 'viem'
import { MASK_VERSION } from './layout'
import { checkMasks, selectBids, type SubmittedBid, type SubmittedMask } from './selection'

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

  it('takes a bid of 4 ciphertexts (the no-provider type) whole or not at all', () => {
    const tree = new Tree()
    const all = [true, true, true, true]
    // The second share of Alice's update does not open, so her first bid counts, before Bob.
    expect(picked([tree.bid(alice, 1, all), tree.bid(bob, 1, all), tree.bid(alice, 2, [true, true, true, false])])).toEqual([
      [alice, 1, 0],
      [bob, 1, 1],
    ])
    // Alice's only bid has a bad share: she is dropped whole.
    expect(picked([tree.bid(alice, 1, [true, true, false, true]), tree.bid(bob, 1, all)])).toEqual([[bob, 1, 0]])
  })

  it('keeps the place of an earlier bid when the update does not open', () => {
    const tree = new Tree()
    // Alice's update is skipped, so her first bid counts at its own place, before Bob.
    expect(picked([tree.bid(alice, 1), tree.bid(bob, 1), tree.bid(alice, 2, [true, false, true])])).toEqual([
      [alice, 1, 0],
      [bob, 1, 1],
    ])
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

const carol = '0x3333333333333333333333333333333333333333'

/** The mask of `provider` at leaf `index`; `good` says whether it opens its commitment. */
const maskOf = (provider: `0x${string}`, index: number, good = true): SubmittedMask => {
  const ciphertext = `0x77${index}${provider.slice(2, 4)}` as Hex
  return { provider, index, ciphertext, commitment: good ? commitmentOf(ciphertext) : '0xdead' }
}

describe('selectBids with masks', () => {
  it('skips an entry with the mask version, and the bids around it count', () => {
    const tree = new Tree()
    const bids = [tree.bid(alice, MASK_VERSION, [true]), tree.bid(bob, 1), tree.bid(alice, 1)]
    // The mask leaf of alice does not make her a bidder, and does not take the place of her bid.
    expect(picked(bids)).toEqual([
      [bob, 1, 0],
      [alice, 1, 1],
    ])
  })

  it('never lets the mask version win against a bid of the same address', () => {
    const tree = new Tree()
    expect(picked([tree.bid(alice, 1), tree.bid(alice, MASK_VERSION, [true])])).toEqual([[alice, 1, 0]])
  })
})

describe('checkMasks', () => {
  const providers: `0x${string}`[] = [alice, bob, carol]

  it('is complete when every provider has a mask that opens', () => {
    const masks = [maskOf(alice, 1), maskOf(bob, 2), maskOf(carol, 3)]
    expect(checkMasks(masks, providers, opens)).toEqual({ complete: true, missing: [], invalid: [] })
  })

  it('lists the providers that sent no mask, in the order of the auction', () => {
    expect(checkMasks([maskOf(bob, 1)], providers, opens)).toEqual({ complete: false, missing: [alice, carol], invalid: [] })
    expect(checkMasks([], providers, opens)).toEqual({ complete: false, missing: providers, invalid: [] })
  })

  it('lists the providers whose mask does not open its commitment', () => {
    const masks = [maskOf(alice, 1), maskOf(bob, 2, false), maskOf(carol, 3)]
    expect(checkMasks(masks, providers, opens)).toEqual({ complete: false, missing: [], invalid: [bob] })
  })

  it('ignores a mask from an address that is no provider', () => {
    const stranger = '0x4444444444444444444444444444444444444444'
    const masks = [maskOf(stranger, 1, false), maskOf(alice, 2)]
    expect(checkMasks(masks, [alice], opens)).toEqual({ complete: true, missing: [], invalid: [] })
  })

  it('treats addresses that differ only in case as one provider, and reports it as the auction names it', () => {
    const checksummed: `0x${string}` = '0xAbCdEf0000000000000000000000000000000001'
    const masks = [maskOf(checksummed.toLowerCase() as `0x${string}`, 1, false)]
    expect(checkMasks(masks, [checksummed], opens)).toEqual({ complete: false, missing: [], invalid: [checksummed] })
  })

  it('counts the mask with the lowest leaf of a provider', () => {
    expect(checkMasks([maskOf(alice, 5, false), maskOf(alice, 2)], [alice], opens).complete).toBe(true)
    expect(checkMasks([maskOf(alice, 2, false), maskOf(alice, 5)], [alice], opens)).toEqual({
      complete: false,
      missing: [],
      invalid: [alice],
    })
  })
})
