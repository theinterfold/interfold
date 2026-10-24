// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { computeCiphertextCommitment } from '@interfold/sdk'
import { bytesToHex, hexToBytes, stringToBytes, zeroAddress, type Address, type Hex } from 'viem'

/** The preset name that the SDK and the program use. */
export const PRESET = 'INSECURE_THRESHOLD_SIMD' as const

/** The prefix of the configuration input. `SealedCcaProgram.CONFIG_DOMAIN` and `CONFIG_DOMAIN` in `program/src/lib.rs` are the same bytes. */
export const CONFIG_DOMAIN = 'interfold-sealed-cca-config-v1'

/** The zero commitment of the configuration input. */
const ZERO_COMMITMENT = `0x${'00'.repeat(32)}`

/** The most bids of one bidder. `SealedCcaProgram.MAX_BIDS_PER_BIDDER`. */
export const MAX_BIDS_PER_BIDDER = 3

/** The fewest counted bidders for which the program runs. A sale with none has no output. */
export const MIN_BIDDERS = 1

/** Input 0 of a round: the domain bytes followed by the reveal mode byte. */
export function saleConfigInput(revealMode: number): Hex {
  if (!Number.isInteger(revealMode) || revealMode < 0 || revealMode > 255) throw new Error(`Invalid reveal mode ${revealMode}`)
  return bytesToHex(Uint8Array.from([...stringToBytes(CONFIG_DOMAIN), revealMode]))
}

/** One `BidSubmitted` event: a bid of one bidder. It is one ciphertext and one leaf. */
export interface SubmittedBid {
  bidder: Address
  /** The version of the bid: 1 for the first bid of the bidder, 2 for its first update, and so on. */
  version: number
  /** The leaf index of the bid. Leaf 0 is the configuration. */
  leafIndex: number
  ciphertext: Hex
  commitment: Hex
}

/**
 * The inputs of a round in the shape of the program runner request. The four lists have one entry
 * per input, in leaf order; `ciphertexts` holds `[bytes, leaf index]`.
 *
 * Index 0 is the configuration: a zero commitment, the zero address and version 0. Every other
 * input is one bid ciphertext: its commitment, the bidder (the runner's "slot") and the bid
 * version (the runner's "parent"). The runner turns the slot and the version into the 25-byte
 * metadata of the leaf.
 */
export interface ProgramInputs {
  ciphertexts: Array<[string, number]>
  commitments: string[]
  slots: string[]
  parents: number[]
}

/**
 * Every published input of a sale in leaf order: the configuration at leaf 0, then the ciphertext
 * of every bid, whether or not the program will count it. The input root covers all leaves, so the
 * program needs all of them. Events do not arrive in leaf order, so this sorts them.
 *
 * Throws if the leaves are not 1, 2, 3, ... without a gap, which means an event is missing.
 */
export function saleInputs(revealMode: number, bids: readonly SubmittedBid[]): ProgramInputs {
  const inputs: ProgramInputs = {
    ciphertexts: [[saleConfigInput(revealMode), 0]],
    commitments: [ZERO_COMMITMENT],
    slots: [zeroAddress],
    parents: [0],
  }
  for (const bid of [...bids].sort((a, b) => a.leafIndex - b.leafIndex)) {
    if (bid.leafIndex !== inputs.ciphertexts.length) {
      throw new Error(`Leaf ${inputs.ciphertexts.length} has no bid event; the next one is leaf ${bid.leafIndex}`)
    }
    inputs.ciphertexts.push([bid.ciphertext, bid.leafIndex])
    inputs.commitments.push(bid.commitment)
    inputs.slots.push(bid.bidder)
    inputs.parents.push(bid.version)
  }
  return inputs
}

/**
 * The bids that the program counts. This is the rule of `select_bids` in `program/src/lib.rs`: for
 * each bidder, the bid with the highest version whose bytes open their commitment. A bidder with no
 * such bid is dropped. `opens(ciphertext, commitment)` recomputes the SAFE commitment of the bytes
 * and compares it with `commitment`. The result is in leaf order.
 */
export function selectBids(bids: readonly SubmittedBid[], opens: (ciphertext: Hex, commitment: Hex) => boolean): SubmittedBid[] {
  const latest = new Map<string, SubmittedBid>()
  for (const bid of bids) {
    if (!opens(bid.ciphertext, bid.commitment)) continue
    const key = bid.bidder.toLowerCase()
    const chosen = latest.get(key)
    if (!chosen || chosen.version < bid.version) latest.set(key, bid)
  }
  return [...latest.values()].sort((a, b) => a.leafIndex - b.leafIndex)
}

/**
 * The `opens` function of `selectBids` for these bids. It recomputes the SAFE commitment of every
 * ciphertext once, with the same function the bid proof uses, and compares it with the commitment of
 * the bid. A ciphertext that does not deserialize opens nothing.
 */
export async function opensCommitment(bids: readonly SubmittedBid[]): Promise<(ciphertext: Hex, commitment: Hex) => boolean> {
  const recomputed = new Map<Hex, Hex | undefined>()
  await Promise.all(
    bids.map(async ({ ciphertext }) => {
      recomputed.set(ciphertext, await computeCiphertextCommitment(hexToBytes(ciphertext), PRESET).then(bytesToHex, () => undefined))
    }),
  )
  return (ciphertext, commitment) => recomputed.get(ciphertext)?.toLowerCase() === commitment.toLowerCase()
}
