// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * Resolving a slot's head from the chain.
 *
 * These tests exist because the rule being reproduced lives in the guest, in Rust
 * (`e3_user_program::policy::chain_head_per_slot`), and a divergence between the two is silent: a
 * client that resolves a different head builds a ballot that proves, publishes, costs gas, and is
 * then dropped from the tally with no error anywhere.
 *
 * Real ciphertexts and real commitments throughout. A mocked commitment would pass whatever the
 * walk did with the bytes, which is the part that matters.
 */

import { describe, expect, it, beforeAll } from 'vitest'
import { keccak256 } from 'viem'

import { resolveSlotHead } from '../src/slotHead'
import { getZkInputsGenerator } from '../src/encoding'
import type { OnChainInputRecord, SlotEntry } from '../src/types'

/** A real BFV ciphertext, and the commitment the circuit constrains for it. */
type Ballot = { ciphertext: Uint8Array; commitment: `0x${string}`; hash: `0x${string}` }

const hex = (bytes: Uint8Array): `0x${string}` =>
  `0x${Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')}` as `0x${string}`

describe('resolveSlotHead', () => {
  let ballots: Ballot[]

  beforeAll(() => {
    const generator = getZkInputsGenerator()
    const { publicKey } = generator.generateKeys()
    const degree = Number(generator.getBFVParams().degree)

    ballots = [0, 1, 2, 3].map((seed) => {
      const vote = new BigInt64Array(degree)
      vote[0] = BigInt(seed + 1)

      const ciphertext = generator.encryptVote(publicKey, vote)

      return {
        ciphertext,
        commitment: hex(generator.computeCtCommitment(ciphertext)),
        hash: keccak256(ciphertext),
      }
    })
  })

  /** The chain's record of an entry whose bytes are `ballot`. */
  const record = (index: number, ballot: Ballot, parentIndexPlusOne: number): OnChainInputRecord => ({
    index,
    encryptedVoteCommitment: ballot.commitment,
    encryptedVoteHash: ballot.hash,
    parentIndexPlusOne,
  })

  const entry = (index: number, ballot: Ballot): SlotEntry => ({ index, ciphertext: ballot.ciphertext })

  it('reports no head for a slot with no entries', () => {
    const resolved = resolveSlotHead([], [])

    expect(resolved.head).toBeUndefined()
    expect(resolved.complete).toBe(true)
  })

  it('takes the end of a chain of good entries', () => {
    const entries = [entry(0, ballots[0]), entry(1, ballots[1]), entry(2, ballots[2])]
    const records = [record(0, ballots[0], 0), record(1, ballots[1], 1), record(2, ballots[2], 2)]

    const resolved = resolveSlotHead(entries, records)

    expect(resolved.head?.index).toBe(2)
    expect(resolved.head?.ciphertext).toEqual(ballots[2].ciphertext)
    expect(resolved.complete).toBe(true)
  })

  /**
   * The case a backwards scan gets wrong.
   *
   * Entry 1 is poisoned, so the guest skips it. Entry 2 is a perfectly good ciphertext, but it
   * extends entry 1, which the guest never made the head — so the guest skips entry 2 as well and
   * the slot is still held by entry 0. A client that scanned back from the newest entry and
   * stopped at the first one whose bytes verify would answer 2 and lose the vote.
   */
  it('does not take a good entry that extends a skipped one', () => {
    const entries = [entry(0, ballots[0]), entry(1, ballots[1]), entry(2, ballots[2])]
    const records = [
      record(0, ballots[0], 0),
      // Published bytes that do not reproduce the commitment the proof constrained.
      { ...record(1, ballots[1], 1), encryptedVoteCommitment: ballots[3].commitment },
      record(2, ballots[2], 2),
    ]

    const resolved = resolveSlotHead(entries, records)

    expect(resolved.head?.index).toBe(0)
    expect(resolved.complete).toBe(true)
    expect(resolved.rejected).toEqual([
      { index: 1, reason: 'commitment-mismatch' },
      { index: 2, reason: 'not-extending-head' },
    ])
  })

  /**
   * A poisoned entry must not close the slot.
   *
   * An entry nobody can open is never the head, so it is never a valid parent either, and the next
   * honest input names the same parent it did. That is what keeps a slot maskable — and a slot
   * nobody can mask is one where every later input is provably its owner voting again.
   */
  it('keeps the slot writable when an entry is poisoned', () => {
    const entries = [entry(0, ballots[0]), entry(1, ballots[1]), entry(2, ballots[2])]
    const records = [
      record(0, ballots[0], 0),
      { ...record(1, ballots[1], 1), encryptedVoteCommitment: ballots[3].commitment },
      // Names entry 0 as its parent, which is still the head, so this one is taken.
      record(2, ballots[2], 1),
    ]

    const resolved = resolveSlotHead(entries, records)

    expect(resolved.head?.index).toBe(2)
    expect(resolved.complete).toBe(true)
  })

  /**
   * Two entries extending the same parent: the first wins.
   *
   * The guest takes the first usable entry to extend a parent, so a later sibling is dropped. The
   * client has to agree, or it names a parent the tally will not have selected.
   */
  it('takes the first of two entries extending the same parent', () => {
    const entries = [entry(0, ballots[0]), entry(1, ballots[1]), entry(2, ballots[2])]
    const records = [record(0, ballots[0], 0), record(1, ballots[1], 1), record(2, ballots[2], 1)]

    const resolved = resolveSlotHead(entries, records)

    expect(resolved.head?.index).toBe(1)
    expect(resolved.rejected).toEqual([{ index: 2, reason: 'not-extending-head' }])
  })

  /**
   * A server that answers with bytes the contract never recorded.
   *
   * The content hash is what `CRISPProgram` stored when it accepted the proof, so bytes that do
   * not reproduce it did not come from this input. The entry cannot be judged, which is not the
   * same as judging it unusable — hence incomplete.
   */
  it('refuses substituted bytes and reports the walk as incomplete', () => {
    const entries = [entry(0, ballots[0]), entry(1, ballots[3])]
    const records = [record(0, ballots[0], 0), record(1, ballots[1], 1)]

    const resolved = resolveSlotHead(entries, records)

    expect(resolved.head?.index).toBe(0)
    expect(resolved.complete).toBe(false)
    expect(resolved.rejected).toEqual([{ index: 1, reason: 'bytes-mismatch' }])
  })

  /**
   * An input whose data-availability retrieval has not landed.
   *
   * The Secure Process reads the finished round and will have these bytes, so it can take an entry
   * this walk could not see. Answering with the earlier head as if it were settled is what loses a
   * vote, so the result says it is not settled.
   */
  it('reports the walk as incomplete when bytes are missing for an extending entry', () => {
    const entries = [entry(0, ballots[0])]
    const records = [record(0, ballots[0], 0), record(1, ballots[1], 1)]

    const resolved = resolveSlotHead(entries, records)

    expect(resolved.head?.index).toBe(0)
    expect(resolved.complete).toBe(false)
    expect(resolved.rejected).toEqual([{ index: 1, reason: 'missing-bytes' }])
  })

  /**
   * Missing bytes for an entry that was never going to be taken do not spoil the answer.
   *
   * Entry 2 does not extend the head whatever its bytes are, so not having them costs nothing.
   */
  it('stays complete when the missing entry does not extend the head', () => {
    const entries = [entry(0, ballots[0]), entry(1, ballots[1])]
    const records = [record(0, ballots[0], 0), record(1, ballots[1], 1), record(2, ballots[2], 1)]

    const resolved = resolveSlotHead(entries, records)

    expect(resolved.head?.index).toBe(1)
    expect(resolved.complete).toBe(true)
    expect(resolved.rejected).toEqual([{ index: 2, reason: 'not-extending-head' }])
  })

  /**
   * Bytes that do not deserialize are unusable, not an error.
   *
   * The guest drops such an entry and carries on. Throwing here would let one poisoned entry stop
   * a voter who has a good parent earlier in the chain.
   */
  it('treats undecodable bytes as unusable rather than failing', () => {
    const garbage = new Uint8Array(64).fill(7)
    const entries = [entry(0, ballots[0]), { index: 1, ciphertext: garbage }]
    const records = [record(0, ballots[0], 0), { ...record(1, ballots[1], 1), encryptedVoteHash: keccak256(garbage) }]

    const resolved = resolveSlotHead(entries, records)

    expect(resolved.head?.index).toBe(0)
    expect(resolved.rejected).toEqual([{ index: 1, reason: 'commitment-mismatch' }])
  })

  /**
   * The chain decides which entries exist.
   *
   * An entry the server returns that no `InputCommitted` log covers is not an input, so it can
   * never become the head however good its bytes are.
   */
  it('ignores an entry the chain has no record of', () => {
    const entries = [entry(0, ballots[0]), entry(1, ballots[1])]
    const records = [record(0, ballots[0], 0)]

    const resolved = resolveSlotHead(entries, records)

    expect(resolved.head?.index).toBe(0)
    expect(resolved.complete).toBe(true)
  })

  /** Log order is not guaranteed, and the walk is only well defined in index order. */
  it('resolves in index order whatever order the records arrive in', () => {
    const entries = [entry(2, ballots[2]), entry(0, ballots[0]), entry(1, ballots[1])]
    const records = [record(2, ballots[2], 2), record(0, ballots[0], 0), record(1, ballots[1], 1)]

    const resolved = resolveSlotHead(entries, records)

    expect(resolved.head?.index).toBe(2)
  })
})
