// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { describe, expect, it } from 'vitest'
import { zeroAddress, type Hex } from 'viem'
import { AuctionType, MASK_VERSION, auctionConfigInput, type SubmittedBid } from '@interfold/auction-core'
import type { SubmittedMask } from '@interfold/auction-provider-second-price'
import { auctionInputs, planRun } from './inputs'

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
    const type = AuctionType.FirstPrice
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

  it('takes 4 ciphertexts per bid for the no-provider type', () => {
    const type = AuctionType.QnrSecondPrice
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

const carol = '0x3333333333333333333333333333333333333333'
const providers = [alice, bob] as const

/** A mask of `provider` at leaf `index`. */
const mask = (provider: `0x${string}`, name: string, index: number): SubmittedMask => ({
  provider,
  index,
  ciphertext: `0x${name}` as Hex,
  commitment: `0x${name}c` as Hex,
})

describe('auctionInputs of a mask-provider auction', () => {
  const type = AuctionType.ProviderSecondPrice

  it('puts the providers in the configuration, then the masks, then the bids, in leaf order', () => {
    // Neither the masks nor the bids arrive in leaf order.
    const inputs = auctionInputs(type, [bid(carol, 'cc', 1, 3, 2)], { providers, masks: [mask(bob, 'mb', 2), mask(alice, 'ma', 1)] })
    expect(inputs.ciphertexts).toEqual([
      [auctionConfigInput(type, providers), 0],
      ['0xma', 1],
      ['0xmb', 2],
      ['0xcc0', 3],
      ['0xcc1', 4],
    ])
    expect(inputs.commitments).toEqual([`0x${'00'.repeat(32)}`, '0xmac', '0xmbc', '0xccc0', '0xccc1'])
  })

  it('sends the provider as the sender of a mask and MASK_VERSION as its version', () => {
    const inputs = auctionInputs(type, [bid(carol, 'cc', 1, 3, 2)], { providers, masks: [mask(alice, 'ma', 1), mask(bob, 'mb', 2)] })
    expect(inputs.slots).toEqual([zeroAddress, alice, bob, carol, carol])
    expect(inputs.parents).toEqual([0, MASK_VERSION, MASK_VERSION, 1, 1])
  })

  it('names the providers in leaf 0, so a different list gives a different configuration', () => {
    const first = auctionInputs(type, [], { providers: [alice, bob], masks: [] }).ciphertexts[0][0]
    expect(first).not.toBe(auctionInputs(type, [], { providers: [bob, alice], masks: [] }).ciphertexts[0][0])
    expect(first).not.toBe(auctionInputs(type, [], { providers: [alice], masks: [] }).ciphertexts[0][0])
  })

  it('rejects a gap before a mask or between the masks and the bids', () => {
    expect(() => auctionInputs(type, [], { providers, masks: [mask(alice, 'ma', 2)] })).toThrow(/Leaf 1 has no mask event/)
    expect(() =>
      auctionInputs(type, [bid(carol, 'cc', 1, 4, 2)], { providers, masks: [mask(alice, 'ma', 1), mask(bob, 'mb', 2)] }),
    ).toThrow(/Leaf 3 has no bid event/)
  })
})

describe('planRun', () => {
  const type = AuctionType.ProviderSecondPrice
  const masks = [mask(alice, 'ma', 1), mask(bob, 'mb', 2)]
  const bids = [bid(carol, 'cc', 1, 3, 2), bid('0x4444444444444444444444444444444444444444', 'dd', 1, 5, 2)]
  const opensAll = () => true

  it('runs a mask-provider auction when every mask is in and 2 bidders count', () => {
    const plan = planRun(type, bids, { providers, masks }, opensAll)
    expect(plan.kind).toBe('run')
    expect(plan.counted).toBe(2)
    if (plan.kind === 'run') expect(plan.inputs.ciphertexts.map(([, leaf]) => leaf)).toEqual([0, 1, 2, 3, 4, 5, 6])
  })

  it('does not run a mask-provider auction with a missing mask, and names the provider', () => {
    const plan = planRun(type, [], { providers, masks: [masks[0]] }, opensAll)
    expect(plan).toMatchObject({ kind: 'skip', counted: 0 })
    expect(plan.kind === 'skip' && plan.reason).toContain(bob)
  })

  it('does not run a mask-provider auction with a mask that does not open its commitment', () => {
    const plan = planRun(type, bids, { providers, masks }, (ciphertext) => ciphertext !== '0xmb')
    expect(plan.kind).toBe('skip')
    expect(plan.kind === 'skip' && plan.reason).toContain(bob)
  })

  it('does not run with fewer than 2 bidders whose bids open their commitments', () => {
    expect(planRun(type, [bids[0]], { providers, masks }, opensAll)).toMatchObject({ kind: 'skip', counted: 1 })
    const plan = planRun(type, bids, { providers, masks }, (ciphertext) => !ciphertext.startsWith('0xdd'))
    expect(plan).toMatchObject({ kind: 'skip', counted: 1 })
  })

  it('runs the first-price type without masks and still needs 2 bidders', () => {
    const first = [bid(alice, 'a1', 1, 1, 3), bid(bob, 'bb', 1, 4, 3)]
    expect(planRun(AuctionType.FirstPrice, first, { providers: [], masks: [] }, opensAll)).toMatchObject({ kind: 'run', counted: 2 })
    expect(planRun(AuctionType.FirstPrice, [first[0]], { providers: [], masks: [] }, opensAll)).toMatchObject({ kind: 'skip', counted: 1 })
  })

  it('runs the no-provider type with 4 ciphertexts per bid and no masks, and still needs 2 bidders', () => {
    const shares = [bid(alice, 'a1', 1, 1, 4), bid(bob, 'bb', 1, 5, 4)]
    const plan = planRun(AuctionType.QnrSecondPrice, shares, { providers: [], masks: [] }, opensAll)
    expect(plan).toMatchObject({ kind: 'run', counted: 2 })
    if (plan.kind === 'run') {
      expect(plan.inputs.ciphertexts.map(([, leaf]) => leaf)).toEqual([0, 1, 2, 3, 4, 5, 6, 7, 8])
      expect(plan.inputs.parents).toEqual([0, 1, 1, 1, 1, 1, 1, 1, 1])
    }
    expect(planRun(AuctionType.QnrSecondPrice, [shares[0]], { providers: [], masks: [] }, opensAll)).toMatchObject({
      kind: 'skip',
      counted: 1,
    })
  })
})
