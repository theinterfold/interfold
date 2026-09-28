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

// The keys and digest of the `crisp_lib::safe_auth` Noir fixtures, so the SDK and the circuit agree
// on the same vectors. Sorted by address: owner0 < owner1 < owner2.
const [owner0, owner1, owner2] = [0, 1, 2]
  .map((i) => privateKeyToAccount(keccak256(toHex(`safe owner ${i}`))))
  .sort((a, b) => (BigInt(a.address) < BigInt(b.address) ? -1 : 1))
const outsider = privateKeyToAccount(keccak256(toHex('outsider')))
const DIGEST = keccak256(toHex('crisp safe_auth test digest'))
// `COMMIT_T2` in `safe_auth.nr`: the three owners with a threshold of two.
const COMMIT_T2 = '0xba2ec3d58e1012ba18bab78e811f30842f2b649bdd251330891a440377df6d44'

const owners = [owner0.address, owner1.address, owner2.address]
const prepared = (censusMode: 'onchain' | 'merkle' = 'onchain') =>
  ({ circuitInputs: { slot_address: owner0.address.toLowerCase() }, censusMode }) as unknown as PreparedBallot
const sign = (account: typeof owner0) => account.sign({ hash: DIGEST })

describe('owner signatures', () => {
  it('commits to the owners and threshold as the circuit fixture does', () => {
    expect(ownersCommitment({ owners, threshold: 2 })).toBe(COMMIT_T2)
  })

  it('orders the signers by address and points each at its owner', async () => {
    // Signed out of order, by owner2 then owner0.
    const inputs = await attachOwnerSignaturesImpl(prepared(), DIGEST, { owners, threshold: 2 }, [await sign(owner2), await sign(owner0)])

    expect(inputs.owner_indices).toEqual(['0', '2', '0'])
    expect(inputs.threshold).toBe('2')
    expect(BigInt(inputs.owners_commitment_hi)).toBe(BigInt(COMMIT_T2.slice(0, 34)))
    expect(BigInt(inputs.owners_commitment_lo)).toBe(BigInt('0x' + COMMIT_T2.slice(34)))
    // The inactive third slot repeats the first, so it holds a valid public key.
    expect(inputs.public_keys_x[2]).toEqual(inputs.public_keys_x[0])
  })

  it('refuses a signature by an account that is not an owner', async () => {
    await expect(
      attachOwnerSignaturesImpl(prepared(), DIGEST, { owners, threshold: 2 }, [await sign(owner0), await sign(outsider)]),
    ).rejects.toThrow(/not an owner/)
  })

  it('counts one owner once, however many times it signed', async () => {
    const twice = await sign(owner1)
    await expect(attachOwnerSignaturesImpl(prepared(), DIGEST, { owners, threshold: 2 }, [twice, twice])).rejects.toThrow(
      /needs 2 owner signatures; got 1/,
    )
  })

  it('refuses owner signatures for a census ballot', async () => {
    await expect(attachOwnerSignaturesImpl(prepared('merkle'), DIGEST, { owners, threshold: 1 }, [await sign(owner0)])).rejects.toThrow(
      /ONCHAIN/,
    )
  })

  it('gives a mask the owner commitment it is handed, and derives a wallet one otherwise', async () => {
    const safeMask = await attachMaskImpl(prepared(), DIGEST, COMMIT_T2)
    expect(BigInt(safeMask.owners_commitment_hi)).toBe(BigInt(COMMIT_T2.slice(0, 34)))

    const walletMask = await attachMaskImpl(prepared(), DIGEST)
    const wallet = ownersCommitment({ owners: [owner0.address], threshold: 1 })
    expect(BigInt(walletMask.owners_commitment_hi)).toBe(BigInt(wallet.slice(0, 34)))
  })
})

describe('withBallotParent', () => {
  const vote = () =>
    ({
      circuitInputs: { is_mask_vote: false, is_first_vote: true, prev_ct_commitment: '0' },
      parentIndexPlusOne: 0,
      censusMode: 'onchain',
    }) as unknown as PreparedBallot

  it('names the parent entry and its commitment, and leaves the original untouched', () => {
    const original = vote()
    const named = withBallotParent(original, { index: 4, commitment: '0x10' })

    expect(named.parentIndexPlusOne).toBe(5)
    expect(named.circuitInputs.is_first_vote).toBe(false)
    expect(named.circuitInputs.prev_ct_commitment).toBe('16')
    expect(original.parentIndexPlusOne).toBe(0)
    expect(original.circuitInputs.prev_ct_commitment).toBe('0')
  })

  it('names no parent for an empty slot', () => {
    const named = withBallotParent(withBallotParent(vote(), { index: 2, commitment: '0x10' }))
    expect(named.parentIndexPlusOne).toBe(0)
    expect(named.circuitInputs.is_first_vote).toBe(true)
    expect(named.circuitInputs.prev_ct_commitment).toBe('0')
  })

  it('refuses a mask, which adds to the head ciphertext itself', () => {
    const mask = { ...vote(), circuitInputs: { ...vote().circuitInputs, is_mask_vote: true } } as PreparedBallot
    expect(() => withBallotParent(mask, { index: 0, commitment: '0x10' })).toThrow(/mask/)
  })
})
