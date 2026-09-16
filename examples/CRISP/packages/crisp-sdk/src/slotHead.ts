// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * Resolving the head of a slot without trusting the CRISP server.
 *
 * A ballot names the entry it extends, and the Secure Process takes an entry only when its bytes
 * reproduce its commitment and it extends the slot's current head. Naming any other entry has the
 * input published, paid for, and then dropped from the tally — with no error anywhere, because the
 * proof is valid and the contract cannot tell the difference.
 *
 * `CRISPProgram` cannot make that check: the commitment is a Poseidon sponge over CRT limbs and
 * the circuit never sees the serialization, so the bytes and the commitment can disagree and only
 * the guest can tell. `state/previous-ciphertext` makes it off chain, which is correct but is the
 * server's own word about the server's own bytes. This module makes it from the chain instead.
 *
 * What is checked, per entry, against the `InputCommitted` log the contract emitted:
 *
 * 1. `keccak256(bytes)` equals `encryptedVoteHash` — these are the published bytes, not a
 *    substitution. Cheap, and it alone catches a lying or stale server.
 * 2. The bytes reproduce `encryptedVoteCommitment` — the Secure Process will accept the entry.
 * 3. The entry extends the head resolved so far — the same rule the guest applies.
 *
 * Step 2 is the expensive one, so it runs only on entries that pass step 3's ordering. Entries
 * that do not extend the head are skipped for free, which is what keeps this cheap when a slot has
 * been flooded with masks: cost follows the length of the selected chain, not the entry count.
 *
 * An entry that extends the head and cannot be judged — because its bytes are missing, or are not
 * the ones the contract recorded — makes the result incomplete rather than changing the head. The
 * Secure Process reads the finished round, so it can take an entry this walk could not see, and a
 * ballot built on an earlier head would then be dropped from the tally.
 */

import { keccak256, toEventSelector } from 'viem'

import { getZkInputsGenerator } from './encoding'
import { getIndexedLogs } from './api'
import { getSlotEntries } from './state'

import type { OnChainInputRecord, ResolvedSlotHead, SlotEntry, SlotEntryRejection } from './types'

/**
 * `InputCommitted`'s topic, derived from the signature rather than written out as a hash.
 *
 * The event is the contract's record of an accepted ballot, and the field order here is what the
 * body of a log is decoded by. Deriving the selector keeps the two together: a change to the event
 * has to be made here, where the decoding is, instead of silently matching no logs.
 */
const INPUT_COMMITTED_TOPIC = toEventSelector('InputCommitted(uint256,bytes32,address,bytes32,bytes32,uint40,uint40)')

/**
 * The commitment of a ciphertext, as a 32-byte hex string, or `undefined` when the bytes do not
 * deserialize.
 *
 * Bytes that do not deserialize are unusable rather than an error: the Secure Process drops such
 * an entry and carries on, so resolving a head must do the same. Throwing here would let one
 * poisoned entry stop a voter who has a perfectly good parent earlier in the chain.
 */
const commitmentOf = (ciphertext: Uint8Array): `0x${string}` | undefined => {
  try {
    const commitment = getZkInputsGenerator().computeCtCommitment(ciphertext)

    return `0x${Array.from(commitment)
      .map((byte) => byte.toString(16).padStart(2, '0'))
      .join('')}` as `0x${string}`
  } catch {
    return undefined
  }
}

/** Compare two hex strings as values, so that case and any `0x` prefix do not decide equality. */
const sameHex = (left: string, right: string): boolean => left.toLowerCase().replace(/^0x/, '') === right.toLowerCase().replace(/^0x/, '')

/**
 * Resolve which entry holds a slot, from the chain's record of the slot and the server's bytes.
 *
 * Replicates `e3_user_program::policy::chain_head_per_slot`. Both must agree: this decides what a
 * client names as its parent, and that one decides what the tally counts.
 *
 * The walk is forwards, in index order, and takes the FIRST usable entry that extends the head.
 * The guest does the same, and the ordering is what makes the result well defined — a later
 * sibling of an entry already taken is dropped, because only the circuit knows whether an entry
 * replaces the slot or adds to it. Resolving backwards from the newest entry would be wrong: an
 * entry that is itself valid can still sit on a parent that was skipped, and the guest never
 * reaches it.
 *
 * @param entries - The slot's entries with their bytes, in any order.
 * @param records - What the contract published for those entries, in any order.
 * @returns The entry that holds the slot, and every entry that was not taken with the reason.
 */
export const resolveSlotHead = (entries: SlotEntry[], records: OnChainInputRecord[]): ResolvedSlotHead => {
  const bytesByIndex = new Map(entries.map((entry) => [entry.index, entry.ciphertext]))
  // Index order, because that is the order the tree was built in and a chain is only ever extended
  // forwards. The chain is the authority on which entries exist; an entry the server returns that
  // the chain has no record of is not an input at all and is ignored.
  const ordered = [...records].sort((left, right) => left.index - right.index)

  const rejected: { index: number; reason: SlotEntryRejection }[] = []
  let head: number | undefined
  let headBytes: Uint8Array | undefined
  let complete = true

  for (const record of ordered) {
    const parent = record.parentIndexPlusOne === 0 ? undefined : record.parentIndexPlusOne - 1

    // Checked before the bytes are looked at, because it costs nothing and rules out most entries
    // on a flooded slot. An entry that does not extend the head is skipped by the guest whatever
    // its bytes are, so its bytes never need to be fetched or hashed.
    if (parent !== head) {
      rejected.push({ index: record.index, reason: 'not-extending-head' })
      continue
    }

    const ciphertext = bytesByIndex.get(record.index)
    if (!ciphertext) {
      // Normal for an input whose data-availability retrieval has not landed. The entry extends
      // the head, so the Secure Process may well take it once the bytes arrive; answering with an
      // earlier head would have this voter build on a parent the tally has already moved past.
      rejected.push({ index: record.index, reason: 'missing-bytes' })
      complete = false
      continue
    }

    // The published bytes, or a substitution. A mismatch here is not a poisoned input: the
    // contract recorded this hash when it accepted the proof, so these bytes did not come from the
    // input. The server is wrong about this entry, and the real entry stays unjudged.
    if (!sameHex(keccak256(ciphertext), record.encryptedVoteHash)) {
      rejected.push({ index: record.index, reason: 'bytes-mismatch' })
      complete = false
      continue
    }

    // The published bytes do not reproduce the commitment the proof constrained. Unlike the two
    // cases above this is a verdict, not a gap: these are the bytes the round will be computed
    // over, and the Secure Process will drop this entry too.
    const commitment = commitmentOf(ciphertext)
    if (!commitment || !sameHex(commitment, record.encryptedVoteCommitment)) {
      rejected.push({ index: record.index, reason: 'commitment-mismatch' })
      continue
    }

    head = record.index
    headBytes = ciphertext
  }

  return {
    head: head !== undefined && headBytes ? { ciphertext: headBytes, index: head } : undefined,
    complete,
    rejected,
  }
}

/**
 * The `InputCommitted` records for one slot of one round.
 *
 * Read from `InputCommitted` rather than `InputPublished` because the contract records the leaf,
 * the commitment, and the parent when it accepts the proof — `InputPublished` follows later, when
 * the data-availability receipt arrives. A client resolving a parent must see every entry that
 * already holds a tree index, including those whose receipt has not landed.
 *
 * `e3Id` and `slotAddress` are both indexed, so this filters to one slot at the node rather than
 * fetching a round's inputs and discarding most of them.
 *
 * @param serverUrl - The base URL of the CRISP server, used for its log endpoint.
 * @param programAddress - The `CRISPProgram` contract.
 * @param e3Id - The round.
 * @param slotAddress - The slot.
 * @param fromBlock - Where to start scanning. Pass the contract's deployment block.
 * @returns One record per committed input of that slot, in the order the logs were returned.
 */
export const getOnChainInputRecords = async (
  serverUrl: string,
  programAddress: string,
  e3Id: bigint,
  slotAddress: string,
  fromBlock?: bigint,
): Promise<OnChainInputRecord[]> => {
  const logs = await getIndexedLogs(serverUrl, {
    address: programAddress,
    topics: [
      INPUT_COMMITTED_TOPIC,
      `0x${e3Id.toString(16).padStart(64, '0')}`,
      // `inputId`, which is not being filtered on.
      null,
      `0x${slotAddress.toLowerCase().replace(/^0x/, '').padStart(64, '0')}`,
    ],
    fromBlock,
  })

  return logs.map((log) => {
    // The four unindexed fields, each padded to a 32-byte word by the ABI encoding.
    const body = log.data.replace(/^0x/, '')
    const word = (position: number) => body.slice(position * 64, (position + 1) * 64)

    return {
      encryptedVoteCommitment: `0x${word(0)}` as `0x${string}`,
      encryptedVoteHash: `0x${word(1)}` as `0x${string}`,
      parentIndexPlusOne: Number(BigInt(`0x${word(2)}`)),
      index: Number(BigInt(`0x${word(3)}`)),
    }
  })
}

/**
 * Resolve the head of a slot from the chain, without trusting the CRISP server's own answer.
 *
 * Use in place of `getPreviousCiphertext` when a wrong parent must not be possible. The server
 * still supplies the bytes — they are not on chain — but every one of them is checked against what
 * `CRISPProgram` recorded, and the walk that picks the head is this client's, not the server's.
 *
 * @param serverUrl - The base URL of the CRISP server.
 * @param programAddress - The `CRISPProgram` contract.
 * @param e3Id - The round.
 * @param slotAddress - The slot.
 * @param fromBlock - Where to start scanning for logs. Pass the contract's deployment block.
 * @returns The resolved head, whether the walk was complete, and every entry it did not take.
 */
export const resolveSlotHeadOnChain = async (
  serverUrl: string,
  programAddress: string,
  e3Id: bigint,
  slotAddress: string,
  fromBlock?: bigint,
): Promise<ResolvedSlotHead> => {
  const [entries, records] = await Promise.all([
    getSlotEntries(serverUrl, e3Id, slotAddress),
    getOnChainInputRecords(serverUrl, programAddress, e3Id, slotAddress, fromBlock),
  ])

  return resolveSlotHead(entries, records)
}
