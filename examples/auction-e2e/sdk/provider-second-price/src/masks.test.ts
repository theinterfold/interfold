// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { describe, expect, it } from 'vitest'
import { decodeAbiParameters, parseAbiParameters, type Address, type Hex } from 'viem'
import { encodeBidInput } from '@interfold/auction-core'
import { checkMasks, encodeMaskInput, type SubmittedMask } from './masks'

const PROVIDER_A: Address = '0x1111111111111111111111111111111111111111'
const alice = PROVIDER_A
const bob = '0x2222222222222222222222222222222222222222'

/** A ciphertext "opens" its commitment when the commitment is `c(<ciphertext>)`. */
const commitmentOf = (ciphertext: Hex): Hex => `0xc${ciphertext.slice(2)}`
const opens = (ciphertext: Hex, commitment: Hex) => commitment === commitmentOf(ciphertext)
const carol = '0x3333333333333333333333333333333333333333'

/** The mask of `provider` at leaf `index`; `good` says whether it opens its commitment. */
const maskOf = (provider: `0x${string}`, index: number, good = true): SubmittedMask => {
  const ciphertext = `0x77${index}${provider.slice(2, 4)}` as Hex
  return { provider, index, ciphertext, commitment: good ? commitmentOf(ciphertext) : '0xdead' }
}

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

describe('encodeMaskInput', () => {
  it('is a bid input with the provider as bidder, one ciphertext and no gate proof or signature', () => {
    const input = { provider: PROVIDER_A, ciphertext: '0xabcd', commitment: `0x${'11'.repeat(32)}`, proof: '0x99' } as const
    const abi = parseAbiParameters('address, bytes[], bytes32[], bytes, bytes, bytes')
    const [bidder, ciphertexts, commitments, proof, gateProof, signature] = decodeAbiParameters(abi, encodeMaskInput(input))
    expect(bidder.toLowerCase()).toBe(PROVIDER_A)
    expect(ciphertexts).toEqual(['0xabcd'])
    expect(commitments).toEqual([input.commitment])
    expect(proof).toBe('0x99')
    expect(gateProof).toBe('0x')
    expect(signature).toBe('0x')
    expect(encodeMaskInput(input)).toBe(
      encodeBidInput({
        bidder: PROVIDER_A,
        ciphertexts: ['0xabcd'],
        commitments: [input.commitment],
        proof: '0x99',
        gateProof: '0x',
        signature: '0x',
      }),
    )
  })
})
