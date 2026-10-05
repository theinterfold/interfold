// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { describe, expect, it } from 'vitest'
import { bytesToHex, keccak256, pad } from 'viem'

import { decodeInputIdentity, encodeSolidityProof } from '../src/envelope'
import { SLOT_ADDRESS } from './constants'

describe('decodeInputIdentity', () => {
  it('reads back the identity of the input that encodeSolidityProof wraps', () => {
    const commitment = `0x${'ab'.repeat(32)}` as const
    const encryptedVote = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])
    // Each public input is a 32-byte field element; the slot address sits in the low 20 bytes.
    const publicInputs = Array.from({ length: 9 }, (_, i) => pad(bytesToHex(new Uint8Array([i + 1]))))
    publicInputs[3] = pad(SLOT_ADDRESS.toLowerCase() as `0x${string}`)
    publicInputs[7] = commitment

    const envelope = encodeSolidityProof({
      publicInputs,
      proof: new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
      encryptedVote,
      parentIndexPlusOne: 42,
    })

    expect(decodeInputIdentity(envelope)).toEqual({
      slotAddress: SLOT_ADDRESS,
      encryptedVoteCommitment: commitment,
      encryptedVoteHash: keccak256(encryptedVote),
      parentIndexPlusOne: 42,
    })
  })
})
