// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { describe, it, expect } from 'vitest'
import { keccak256, toHex } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { attachMaskImpl, attachOwnerSignaturesImpl, ownersCommitment, withBallotParent } from '../src/circuitInputs'
import type { PreparedBallot } from '../src/types'

// The keys and digest of the `crisp_lib::safe_auth` Noir fixtures, sorted by address.
const [owner0, owner1, owner2] = [0, 1, 2]
  .map((i) => privateKeyToAccount(keccak256(toHex(`safe owner ${i}`))))
  .sort((a, b) => (BigInt(a.address) < BigInt(b.address) ? -1 : 1))
const DIGEST = keccak256(toHex('crisp safe_auth test digest'))
// `COMMIT_T2` in `safe_auth.nr`: the three owners with a threshold of two.
const COMMIT_T2 = '0xba2ec3d58e1012ba18bab78e811f30842f2b649bdd251330891a440377df6d44'

const owners = [owner0.address, owner1.address, owner2.address]
const prepared = () =>
  ({ circuitInputs: { slot_address: owner0.address.toLowerCase() }, censusMode: 'onchain' }) as unknown as PreparedBallot
const sign = (account: typeof owner0) => account.sign({ hash: DIGEST })

describe('owner signatures', () => {
  it('commits to the owners and threshold as the circuit fixture does', () => {
    expect(ownersCommitment({ owners, threshold: 2 })).toBe(COMMIT_T2)
  })

  it('orders the signers by address and points each at its owner', async () => {
    const inputs = await attachOwnerSignaturesImpl(prepared(), DIGEST, { owners, threshold: 2 }, [await sign(owner2), await sign(owner0)])

    expect(inputs.owner_indices).toEqual(['0', '2', '0'])
    expect(BigInt(inputs.owners_commitment_hi)).toBe(BigInt(COMMIT_T2.slice(0, 34)))
    // The inactive third slot repeats the first, so it holds a valid public key.
    expect(inputs.public_keys_x[2]).toEqual(inputs.public_keys_x[0])
  })

  it('refuses a signer that is not an owner, and counts one owner once', async () => {
    const outsider = privateKeyToAccount(keccak256(toHex('outsider')))
    const twoOfThree = { owners, threshold: 2 }

    await expect(attachOwnerSignaturesImpl(prepared(), DIGEST, twoOfThree, [await sign(owner0), await sign(outsider)])).rejects.toThrow(
      /not an owner/,
    )
    await expect(attachOwnerSignaturesImpl(prepared(), DIGEST, twoOfThree, [await sign(owner1), await sign(owner1)])).rejects.toThrow(
      /needs 2 owner signatures; got 1/,
    )
  })

  it('refuses an ONCHAIN mask without the owner commitment of the slot', async () => {
    await expect(attachMaskImpl(prepared(), DIGEST)).rejects.toThrow(/ownersCommitment/)
  })
})

describe('withBallotParent', () => {
  const vote = {
    circuitInputs: { is_mask_vote: false, is_first_vote: true, prev_ct_commitment: '0' },
    parentIndexPlusOne: 0,
  } as PreparedBallot
  const parentOf = ({ parentIndexPlusOne, circuitInputs }: PreparedBallot) => [
    parentIndexPlusOne,
    circuitInputs.is_first_vote,
    circuitInputs.prev_ct_commitment,
  ]

  it('names the parent entry, or none for an empty slot, and leaves the original untouched', () => {
    const named = withBallotParent(vote, { index: 4, commitment: '0x10' })

    expect(parentOf(named)).toEqual([5, false, '16'])
    expect(parentOf(withBallotParent(named))).toEqual([0, true, '0'])
    expect(parentOf(vote)).toEqual([0, true, '0'])
  })

  it('refuses a mask, which adds to the head ciphertext itself', () => {
    const mask = { ...vote, circuitInputs: { ...vote.circuitInputs, is_mask_vote: true } }
    expect(() => withBallotParent(mask, { index: 0, commitment: '0x10' })).toThrow(/mask/)
  })
})
