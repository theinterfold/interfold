// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { describe, expect, it } from 'vitest'
import { stringToHex, zeroAddress, type Hex } from 'viem'
import { CONFIG_DOMAIN, completeRoles, negotiationConfigInput, negotiationInputs, type SubmittedOffer } from './inputs'

const seller = '0x1111111111111111111111111111111111111111'
const buyer = '0x2222222222222222222222222222222222222222'

/** An offer with the ciphertexts `0x<name>0`, `0x<name>1`, `0x<name>2` and the commitments `0x<name>0c`, ... */
const offer = (party: `0x${string}`, role: number, name: string): SubmittedOffer => ({
  party,
  role,
  ciphertexts: [0, 1, 2].map((index) => `0x${name}${index}` as Hex),
  commitments: [0, 1, 2].map((index) => `0x${name}${index}c` as Hex),
})

describe('negotiationConfigInput', () => {
  it('is the domain bytes', () => {
    expect(negotiationConfigInput()).toBe(stringToHex('interfold-negotiation-config-v1'))
    expect(negotiationConfigInput()).toBe(stringToHex(CONFIG_DOMAIN))
  })
})

describe('negotiationInputs', () => {
  it('puts the configuration at leaf 0 and the three ciphertexts of every offer at consecutive leaves', () => {
    const inputs = negotiationInputs([offer(buyer, 1, 'bb'), offer(seller, 0, 'ss')])
    expect(inputs.ciphertexts).toEqual([
      [negotiationConfigInput(), 0],
      ['0xbb0', 1],
      ['0xbb1', 2],
      ['0xbb2', 3],
      ['0xss0', 4],
      ['0xss1', 5],
      ['0xss2', 6],
    ])
    expect(inputs.commitments.slice(1)).toEqual(['0xbb0c', '0xbb1c', '0xbb2c', '0xss0c', '0xss1c', '0xss2c'])
    expect(inputs.slots).toEqual([zeroAddress, buyer, buyer, buyer, seller, seller, seller])
  })

  it('sends role * 256 + index as the parent of an offer leaf', () => {
    expect(negotiationInputs([offer(seller, 0, 'ss'), offer(buyer, 1, 'bb')]).parents).toEqual([0, 0, 1, 2, 256, 257, 258])
  })

  it('sends the zero commitment, the zero address and 0 for the configuration', () => {
    expect(negotiationInputs([])).toEqual({
      ciphertexts: [[negotiationConfigInput(), 0]],
      commitments: [`0x${'00'.repeat(32)}`],
      slots: [zeroAddress],
      parents: [0],
    })
  })

  it('refuses an offer with a wrong role or a wrong number of ciphertexts', () => {
    expect(() => negotiationInputs([offer(seller, 2, 'ss')])).toThrow(/role 2/)
    expect(() => negotiationInputs([{ ...offer(seller, 0, 'ss'), ciphertexts: ['0x01'] }])).toThrow(/1 ciphertext/)
  })
})

describe('completeRoles', () => {
  const offers = [offer(seller, 0, 'ss'), offer(buyer, 1, 'bb')]

  it('has both roles when every ciphertext opens its commitment', () => {
    expect([...completeRoles(offers, () => true)].sort()).toEqual([0, 1])
  })

  it('leaves out a role when one of its ciphertexts does not open', () => {
    expect([...completeRoles(offers, (ciphertext) => ciphertext !== '0xbb2')]).toEqual([0])
  })

  it('is empty when no offer exists or none opens', () => {
    expect(completeRoles([], () => true).size).toBe(0)
    expect(completeRoles(offers, () => false).size).toBe(0)
  })
})
