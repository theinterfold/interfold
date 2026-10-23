// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { describe, expect, it } from 'vitest'
import { AuctionType, auctionConfigInput, rolesFor } from '../shared/layout'
import { auctionInputs, type SubmittedCiphertext } from './inputs'

const alice = '0xaaaa'
const bob = '0xbbbb'
const carol = '0xcccc'

/** One ciphertext per role of `type` for each bidder, named `<bidder>/<role>`. */
const submissionsOf = (type: AuctionType, bidders: string[]): SubmittedCiphertext[] =>
  bidders.flatMap((bidder) => rolesFor(type).map((role) => ({ bidder, role, ciphertext: `${bidder}/${role}` })))

describe('auctionInputs', () => {
  it('puts the configuration at leaf 0 and the 3 ciphertexts of each bidder at its leaves, in leaf order', () => {
    const type = AuctionType.RatioFirstPrice
    // Event order is not leaf order: bob submitted first, alice's bid was linked first.
    const inputs = auctionInputs(type, submissionsOf(type, [bob, alice]), [
      { bidder: alice, firstIndex: 1n },
      { bidder: bob, firstIndex: 4n },
    ])
    expect(inputs).toEqual([
      [auctionConfigInput(type), 0],
      ['0xaaaa/0', 1],
      ['0xaaaa/1', 2],
      ['0xaaaa/2', 3],
      ['0xbbbb/0', 4],
      ['0xbbbb/1', 5],
      ['0xbbbb/2', 6],
    ])
  })

  it('takes 4 ciphertexts per bidder for the second-price ratio type, the pair mask last', () => {
    const type = AuctionType.RatioSecondPrice
    const inputs = auctionInputs(type, submissionsOf(type, [alice, bob]), [
      { bidder: bob, firstIndex: 5n },
      { bidder: alice, firstIndex: 1n },
    ])
    expect(inputs.map(([, leaf]) => leaf)).toEqual([0, 1, 2, 3, 4, 5, 6, 7, 8])
    expect(inputs.slice(1).map(([ciphertext]) => ciphertext)).toEqual([
      '0xaaaa/0',
      '0xaaaa/1',
      '0xaaaa/2',
      '0xaaaa/3',
      '0xbbbb/0',
      '0xbbbb/1',
      '0xbbbb/2',
      '0xbbbb/3',
    ])
  })

  it('leaves out a bidder that was not linked', () => {
    const type = AuctionType.RatioSecondPrice
    const submitted = [...submissionsOf(type, [alice, bob]), ...submissionsOf(type, [carol]).slice(0, 3)]
    const inputs = auctionInputs(type, submitted, [
      { bidder: alice, firstIndex: 1n },
      { bidder: bob, firstIndex: 5n },
    ])
    expect(inputs).toHaveLength(1 + 2 * 4)
    expect(inputs.some(([ciphertext]) => ciphertext.startsWith('0xcccc'))).toBe(false)
  })

  it('rejects a linked bidder with a missing ciphertext, rather than computing over a wrong set', () => {
    const type = AuctionType.RatioSecondPrice
    const submitted = submissionsOf(type, [alice]).slice(0, 3)
    expect(() => auctionInputs(type, submitted, [{ bidder: alice, firstIndex: 1n }])).toThrow(/role 3 of linked bidder 0xaaaa/)
  })
})
