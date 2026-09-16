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
 * The bytes come from the server, because they are not on chain. Everything that judges them
 * comes from an independent RPC client: the `InputCommitted` logs, which are the contract's own
 * record of an accepted ballot. That split is what makes the check meaningful — a server that
 * controls both the bytes and the evidence about them could simply omit an entry and its log
 * together, and nothing would be left to notice.
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

import { keccak256 } from 'viem'

import { registeredPreset, type CircuitPreset } from './circuits'
import { getZkInputsGenerator } from './encoding'
import { getSlotEntries } from './state'

import type { PublicClient } from 'viem'
import type { OnChainInputRecord, ResolvedSlotHead, SlotEntry, SlotEntryRejection } from './types'

/**
 * What a chain-backed resolution needs beyond the round and the slot.
 *
 * Both fields are required rather than defaulted. Each default that was considered here produced a
 * silent wrong answer instead of an error: `0` for the scan start made every request unbounded, and
 * the SDK's own generator fell back to insecure-512 parameters when the round's circuits were not
 * loaded, marking every entry unusable.
 */
export type SlotHeadResolution = {
  /** The BFV preset the round's ciphertexts are encrypted under. */
  preset: CircuitPreset
  /** The block `CRISPProgram` was deployed at, where its logs begin. */
  deploymentBlock: bigint
}

/**
 * Blocks per `eth_getLogs` request.
 *
 * The real cap belongs to the provider and is not discoverable over the wire, so this is a width
 * common hosted endpoints accept. The CRISP server's own log route windows at the same width.
 */
const LOG_WINDOW = 2_000n

/**
 * `InputCommitted`, as an ABI event rather than a raw topic list.
 *
 * Declared as an event so viem encodes the topic filter and decodes the body. Naming the fields
 * here is what keeps the two together: a raw topic list would have to be spelled out by hand, and
 * the body would have to be sliced by word offset, which corrupts silently if the event changes.
 */
const INPUT_COMMITTED_EVENT = {
  type: 'event',
  name: 'InputCommitted',
  inputs: [
    { name: 'e3Id', type: 'uint256', indexed: true },
    { name: 'inputId', type: 'bytes32', indexed: true },
    { name: 'slotAddress', type: 'address', indexed: true },
    { name: 'encryptedVoteCommitment', type: 'bytes32', indexed: false },
    { name: 'encryptedVoteHash', type: 'bytes32', indexed: false },
    { name: 'parentIndexPlusOne', type: 'uint40', indexed: false },
    { name: 'index', type: 'uint40', indexed: false },
  ],
} as const

/**
 * The commitment of a ciphertext, as a 32-byte hex string, or `undefined` when the bytes do not
 * deserialize.
 *
 * Bytes that do not deserialize are unusable rather than an error: the Secure Process drops such
 * an entry and carries on, so resolving a head must do the same. Throwing here would let one
 * poisoned entry stop a voter who has a perfectly good parent earlier in the chain.
 */
const commitmentOf = (generator: ZkInputsGenerator, ciphertext: Uint8Array): `0x${string}` | undefined => {
  try {
    const commitment = generator.computeCtCommitment(ciphertext)

    return `0x${Array.from(commitment)
      .map((byte) => byte.toString(16).padStart(2, '0'))
      .join('')}` as `0x${string}`
  } catch {
    return undefined
  }
}

type ZkInputsGenerator = ReturnType<typeof getZkInputsGenerator>

/**
 * The generator that recomputes commitments for one preset, refusing to run under any other.
 *
 * A commitment is only comparable within a single preset. The sponge runs over CRT limbs whose
 * count and width come from the BFV parameters, so a secure-8192 ciphertext hashed with insecure-512
 * parameters does not fail — it returns 32 different bytes. Every entry then reads as
 * `commitment-mismatch`, which is a verdict rather than a gap, so the walk takes no entry at all and
 * still reports `complete: true`. The ballot is built with no parent and the Secure Process drops
 * it, which is exactly the silent vote loss this module exists to prevent.
 *
 * That happens whenever the head is resolved before the round's circuits are loaded, because
 * `getZkInputsGenerator()` falls back to insecure-512 defaults rather than failing. So the preset is
 * required and must already be registered. Throwing is deliberate: this is a caller ordering bug,
 * not a property of the round, and no retry will clear it.
 */
const commitmentGenerator = (preset: CircuitPreset): ZkInputsGenerator => {
  const registered = registeredPreset()

  if (registered !== preset) {
    throw new Error(
      `Cannot resolve a slot head for a ${preset} round: the ${preset} circuits are not loaded ` +
        `(registered: ${registered ?? 'none'}). Load the round's circuits first — under the wrong ` +
        `parameters every entry is judged a commitment mismatch and an occupied slot reads as empty.`,
    )
  }

  return getZkInputsGenerator()
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
 * @param preset - The BFV preset the round's ciphertexts are encrypted under. Required, because a
 *                 commitment recomputed under any other preset is 32 unrelated bytes and would mark
 *                 every entry unusable. The matching circuits must already be registered.
 * @returns The entry that holds the slot, and every entry that was not taken with the reason.
 * @throws When the registered circuit bundle is not for `preset`.
 */
export const resolveSlotHead = (entries: SlotEntry[], records: OnChainInputRecord[], preset: CircuitPreset): ResolvedSlotHead => {
  const generator = commitmentGenerator(preset)
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
    const commitment = commitmentOf(generator, ciphertext)
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
 * **The logs are read through a client the caller supplies, not the CRISP server.** Reading them
 * from the server would make the check that follows circular: the entries come from the same
 * server, so a server that omits an entry *and* its log leaves the walk with no evidence the entry
 * exists, and it answers with a superseded head as though the walk were complete. That is the one
 * failure this module exists to catch, so it must not depend on the source it is checking.
 *
 * **Do not derive `fromBlock` from the round's public state.** `state/lite` reports a `start_block`
 * that is `E3.request_block`, and that field holds a unix timestamp rather than a height
 * (`crates/tests/tests/integration.rs` builds it from `SystemTime`). Its `snapshot_block` falls back
 * to `request_block - 1`, so it is a timestamp too when no token snapshot was recorded. Either one
 * passed here is rejected by the node as an invalid block range and no logs come back at all.
 *
 * @param client - A viem client pointed at an endpoint the caller trusts for log reads.
 * @param programAddress - The `CRISPProgram` contract.
 * @param e3Id - The round.
 * @param slotAddress - The slot.
 * @param deploymentBlock - The block `CRISPProgram` was deployed at. Required, and there is no safe
 *                          default: the contract has no logs before it, so starting earlier only
 *                          spends requests. It must be a block number, and everything the round's
 *                          public state reports is a timestamp rather than a height (`state/lite`'s
 *                          `start_block` is `E3.request_block`, which
 *                          `crates/tests/tests/integration.rs` builds from `SystemTime`, and its
 *                          `snapshot_block` falls back to `request_block - 1`) — either one passed
 *                          here is rejected by the node as an invalid block range and no logs come
 *                          back at all.
 * @returns One record per committed input of that slot.
 */
export const getOnChainInputRecords = async (
  client: PublicClient,
  programAddress: string,
  e3Id: bigint,
  slotAddress: string,
  deploymentBlock: bigint,
): Promise<OnChainInputRecord[]> => {
  // Pinned before the first request, so the range cannot shift under the scan: a head that advances
  // between windows would make the next range either overlap or skip.
  const head = await client.getBlockNumber()
  const records: OnChainInputRecord[] = []

  // Windowed, because the provider's `eth_getLogs` range cap is not discoverable over the wire and
  // an unbounded request is refused outright by every hosted endpoint. The server's own route uses
  // the same width for the same reason. A deployment block is what makes this affordable: the scan
  // is bounded by how long the contract has existed, not by the age of the chain.
  for (let start = deploymentBlock; start <= head; start += LOG_WINDOW) {
    const windowEnd = start + LOG_WINDOW - 1n
    const logs = await client.getLogs({
      address: programAddress as `0x${string}`,
      event: INPUT_COMMITTED_EVENT,
      args: { e3Id, slotAddress: slotAddress as `0x${string}` },
      fromBlock: start,
      toBlock: windowEnd < head ? windowEnd : head,
    })

    for (const log of logs) {
      records.push({
        encryptedVoteCommitment: log.args.encryptedVoteCommitment as `0x${string}`,
        encryptedVoteHash: log.args.encryptedVoteHash as `0x${string}`,
        parentIndexPlusOne: Number(log.args.parentIndexPlusOne),
        index: Number(log.args.index),
      })
    }
  }

  return records
}

/**
 * Resolve the head of a slot from the chain, without trusting the CRISP server's own answer.
 *
 * Use in place of `getPreviousCiphertext` when a wrong parent must not be possible. The server
 * still supplies the bytes — they are not on chain: `InputPublished` carries the Avail coordinates
 * rather than the ciphertext — but every one of them is checked against what `CRISPProgram`
 * recorded, and both the logs and the walk that picks the head are this client's.
 *
 * The two sources are deliberately different. Entries come from the server because only it holds
 * the bytes; the `InputCommitted` logs come from `client` because they are what proves those bytes
 * belong to this slot. Reading both from the server would let it omit an entry and its log
 * together, leaving nothing to notice the gap.
 *
 * @param client - A viem client pointed at an endpoint the caller trusts for log reads.
 * @param serverUrl - The base URL of the CRISP server, used only to fetch entry bytes.
 * @param programAddress - The `CRISPProgram` contract.
 * @param e3Id - The round.
 * @param slotAddress - The slot.
 * @param preset - The BFV preset the round's ciphertexts are encrypted under, and the preset whose
 *                 circuits must already be registered.
 * @param deploymentBlock - The block `CRISPProgram` was deployed at, and where the log scan starts.
 * @returns The resolved head, whether the walk was complete, and every entry it did not take.
 * @throws When the registered circuits are not for `preset`, or when the round's circuits were never
 *         loaded at all. Refusing beats resolving a head under the wrong parameters.
 */
export const resolveSlotHeadOnChain = async (
  client: PublicClient,
  serverUrl: string,
  programAddress: string,
  e3Id: bigint,
  slotAddress: string,
  { preset, deploymentBlock }: SlotHeadResolution,
): Promise<ResolvedSlotHead> => {
  const [entries, records] = await Promise.all([
    getSlotEntries(serverUrl, e3Id, slotAddress),
    getOnChainInputRecords(client, programAddress, e3Id, slotAddress, deploymentBlock),
  ])

  return resolveSlotHead(entries, records, preset)
}
