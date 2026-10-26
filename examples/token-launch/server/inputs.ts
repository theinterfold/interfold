// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { computeCiphertextCommitment } from '@interfold/sdk'
import { bytesToHex, hexToBytes, zeroAddress, type Address, type Hex } from 'viem'
// The layout of the config input has one source, the SDK. The server reads the TypeScript file, not
// `dist`, so it needs no SDK build to run or to be tested.
import { MAX_BIDDERS, PRESET } from '../sdk/src/layout'

export { PRESET }

/** The zero commitment of the configuration input. */
const ZERO_COMMITMENT = `0x${'00'.repeat(32)}`

/** The fewest counted bidders for which the program runs. A sale with none has no output. */
export const MIN_BIDDERS = 1

/**
 * One `BidSubmitted` event, seen from one round: the ciphertext and the commitment that this round's
 * E3 holds. A bid is one leaf in each of the two E3s, at the same place.
 */
export interface SubmittedBid {
  bidder: Address
  /** The bid index. It is the place of the bid in the claim tree and in the input trees after the config leaf. */
  index: number
  ciphertext: Hex
  commitment: Hex
}

/**
 * The inputs of a round in the shape of the program runner request. The four lists have one entry
 * per input, in leaf order; `ciphertexts` holds `[bytes, leaf index]`.
 *
 * Index 0 is the config: a zero commitment, the zero address and the parent 0. Every other input is
 * one bid ciphertext: its commitment, the bidder (the runner's "slot") and the bid index (the
 * runner's "parent"). The runner turns them into the 25-byte metadata `bidder || uint40 index` of the leaf.
 */
export interface ProgramInputs {
  ciphertexts: Array<[string, number]>
  commitments: string[]
  slots: string[]
  parents: number[]
}

/**
 * Every published input of a round in leaf order: the config at leaf 0, then the ciphertext of every
 * bid, whether or not the program will count it. The input root covers all leaves, so the program
 * needs all of them. Events do not arrive in leaf order, so this sorts them by bid index.
 *
 * Throws if the indices are not 0, 1, 2, ... without a gap, which means an event is missing.
 */
export function roundInputs(config: Hex, bids: readonly SubmittedBid[]): ProgramInputs {
  const inputs: ProgramInputs = {
    ciphertexts: [[config, 0]],
    commitments: [ZERO_COMMITMENT],
    slots: [zeroAddress],
    parents: [0],
  }
  for (const bid of [...bids].sort((a, b) => a.index - b.index)) {
    const leaf = bid.index + 1
    if (leaf !== inputs.ciphertexts.length) {
      throw new Error(`Leaf ${inputs.ciphertexts.length} has no bid event; the next one is leaf ${leaf}`)
    }
    inputs.ciphertexts.push([bid.ciphertext, leaf])
    inputs.commitments.push(bid.commitment)
    inputs.slots.push(bid.bidder)
    inputs.parents.push(bid.index)
  }
  return inputs
}

/**
 * The bids that the program counts. This is the rule of `select_bids` in `program/src/lib.rs`: every
 * bid whose bytes open their commitment, in leaf order, and at most `MAX_BIDDERS` of them. A sale has
 * one bid per address, so there is no version to compare. `opens(ciphertext, commitment)` recomputes
 * the SAFE commitment of the bytes and compares it with `commitment`.
 */
export function selectBids(bids: readonly SubmittedBid[], opens: (ciphertext: Hex, commitment: Hex) => boolean): SubmittedBid[] {
  return bids
    .filter((bid) => opens(bid.ciphertext, bid.commitment))
    .sort((a, b) => a.index - b.index)
    .slice(0, MAX_BIDDERS)
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
