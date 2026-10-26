// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { describe, expect, it, vi } from 'vitest'
import { zeroAddress, type Address, type Hex } from 'viem'
import { computeCiphertextCommitment } from '@interfold/sdk'
import { MAX_BIDDERS } from '../sdk/src/layout'
import { opensCommitment, roundInputs, selectBids, type SubmittedBid } from './inputs'

// The SDK root loads the proving backend and the WASM build. The code under test only calls the
// commitment function (here a stub) and never decodes a plaintext, so the tests do not need either.
vi.mock('@interfold/sdk', () => ({ computeCiphertextCommitment: vi.fn(), decodePlaintextSlots: vi.fn() }))

const alice = '0x1111111111111111111111111111111111111111'
const bob = '0x2222222222222222222222222222222222222222'
const config = '0xc0ffee' as Hex

/** A bid with the ciphertext `0x<name>` and the commitment `0x<name>c`. */
const bid = (bidder: Address, name: string, index: number): SubmittedBid => ({
  bidder,
  index,
  ciphertext: `0x${name}` as Hex,
  commitment: `0x${name}c` as Hex,
})

describe('roundInputs', () => {
  it('puts the config at leaf 0 and the ciphertext of every bid after it, in bid order', () => {
    // Event order is not bid order.
    const inputs = roundInputs(config, [bid(bob, 'bb', 1), bid(alice, 'aa', 0), bid(alice, 'cc', 2)])
    expect(inputs.ciphertexts).toEqual([
      [config, 0],
      ['0xaa', 1],
      ['0xbb', 2],
      ['0xcc', 3],
    ])
    expect(inputs.commitments.slice(1)).toEqual(['0xaac', '0xbbc', '0xccc'])
    expect(inputs.slots).toEqual([zeroAddress, alice, bob, alice])
  })

  it('sends the bid index as the parent, which the runner packs as the uint40 of the leaf metadata', () => {
    expect(roundInputs(config, [bid(alice, 'aa', 0), bid(bob, 'bb', 1)]).parents).toEqual([0, 0, 1])
  })

  it('sends the zero commitment, the zero address and 0 for the config', () => {
    expect(roundInputs(config, [])).toEqual({
      ciphertexts: [[config, 0]],
      commitments: [`0x${'00'.repeat(32)}`],
      slots: [zeroAddress],
      parents: [0],
    })
  })

  it('keeps the bytes of the round that it is given', () => {
    // Round 1 and round 2 hold different ciphertexts of the same bids, at the same leaves.
    const round1 = roundInputs(config, [bid(alice, 'a1', 0)])
    const round2 = roundInputs('0xbeef', [bid(alice, 'a2', 0)])
    expect(round1.ciphertexts[1]).toEqual(['0xa1', 1])
    expect(round2.ciphertexts).toEqual([
      ['0xbeef', 0],
      ['0xa2', 1],
    ])
  })

  it('refuses a round with a missing bid event', () => {
    expect(() => roundInputs(config, [bid(alice, 'aa', 0), bid(bob, 'bb', 2)])).toThrow(/Leaf 2 has no bid event/)
    expect(() => roundInputs(config, [bid(alice, 'aa', 1)])).toThrow(/Leaf 1 has no bid event/)
  })
})

describe('selectBids', () => {
  it('takes every bid that opens its commitment, in bid order', () => {
    const bids = [bid(alice, 'a1', 2), bid(bob, 'bb', 0), bid(alice, 'a2', 1)]
    expect(selectBids(bids, () => true).map((selected) => selected.ciphertext)).toEqual(['0xbb', '0xa2', '0xa1'])
  })

  it('drops a bid that does not open its commitment', () => {
    const bids = [bid(alice, 'a1', 0), bid(bob, 'bb', 1)]
    expect(selectBids(bids, (ciphertext) => ciphertext === '0xbb').map((selected) => selected.bidder)).toEqual([bob])
    expect(selectBids(bids, () => false)).toEqual([])
  })

  it('takes at most MAX_BIDDERS bids, the first in bid order', () => {
    const bids = Array.from({ length: MAX_BIDDERS + 3 }, (_, index) => bid(alice, index.toString(16).padStart(2, '0'), index))
    const selected = selectBids(bids, () => true)
    expect(selected).toHaveLength(MAX_BIDDERS)
    expect(selected.at(-1)?.index).toBe(MAX_BIDDERS - 1)
  })
})

describe('opensCommitment', () => {
  it('opens a bid whose recomputed commitment equals the published one, without regard to case', async () => {
    vi.mocked(computeCiphertextCommitment).mockImplementation(async (bytes) => Uint8Array.from([bytes[0], 0xab]))
    const bids = [
      { ...bid(alice, '01', 0), commitment: '0x01aB' as Hex },
      { ...bid(bob, '02', 1), commitment: '0x01ab' as Hex },
    ]
    const opens = await opensCommitment(bids)
    expect(opens(bids[0].ciphertext, bids[0].commitment)).toBe(true)
    expect(opens(bids[1].ciphertext, bids[1].commitment)).toBe(false)
  })

  it('opens nothing for a ciphertext that does not deserialize', async () => {
    vi.mocked(computeCiphertextCommitment).mockRejectedValue(new Error('not a ciphertext'))
    const bids = [bid(alice, '01', 0)]
    const opens = await opensCommitment(bids)
    expect(opens(bids[0].ciphertext, bids[0].commitment)).toBe(false)
  })
})
