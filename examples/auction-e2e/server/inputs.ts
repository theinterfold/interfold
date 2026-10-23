// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { computeCiphertextCommitment } from '@interfold/sdk'
import { bytesToHex, hexToBytes, zeroAddress, type Hex } from 'viem'
import { type AuctionType, auctionConfigInput, PRESET } from '../shared/layout'
import type { SubmittedBid } from '../shared/selection'

/** The zero commitment of the configuration input. */
const ZERO_COMMITMENT = `0x${'00'.repeat(32)}`

/**
 * The inputs of a round in the shape of the program runner request. The four lists have one entry
 * per input, in leaf order; `ciphertexts` holds `[bytes, leaf index]`.
 *
 * Index 0 is the configuration: a zero commitment, the zero address and version 0. Every other
 * input is one ciphertext of a bid: its commitment, the bidder (the runner's "slot") and the bid
 * version (the runner's "parent", which the auction reads as a version). The program turns the
 * slot and the version into the 25-byte metadata of the leaf.
 */
export interface ProgramInputs {
  ciphertexts: Array<[string, number]>
  commitments: string[]
  slots: string[]
  parents: number[]
}

/**
 * Every published input of an auction in leaf order: the configuration at leaf 0, then the
 * ciphertexts of every bid, whether or not the program will count it. The input root covers all
 * leaves, so the program needs all of them. Events do not arrive in leaf order, so this sorts them.
 *
 * Throws if the leaves are not 1, 2, 3, ... without a gap, which means an event is missing.
 */
export function auctionInputs(type: AuctionType, bids: readonly SubmittedBid[]): ProgramInputs {
  const inputs: ProgramInputs = {
    ciphertexts: [[auctionConfigInput(type), 0]],
    commitments: [ZERO_COMMITMENT],
    slots: [zeroAddress],
    parents: [0],
  }
  for (const bid of [...bids].sort((a, b) => a.firstIndex - b.firstIndex)) {
    if (bid.ciphertexts.length !== bid.commitments.length) {
      throw new Error(
        `Bid ${bid.version} of ${bid.bidder} has ${bid.ciphertexts.length} ciphertexts and ${bid.commitments.length} commitments`,
      )
    }
    bid.ciphertexts.forEach((ciphertext, role) => {
      if (bid.firstIndex + role !== inputs.ciphertexts.length) {
        throw new Error(`Leaf ${inputs.ciphertexts.length} has no bid event; the next one starts at leaf ${bid.firstIndex + role}`)
      }
      inputs.ciphertexts.push([ciphertext, bid.firstIndex + role])
      inputs.commitments.push(bid.commitments[role])
      inputs.slots.push(bid.bidder)
      inputs.parents.push(bid.version)
    })
  }
  return inputs
}

/**
 * The `opens` function of `selectBids` for these bids. It recomputes the SAFE commitment of every
 * ciphertext once, with the same function the bid proof uses, and compares it with the commitment of
 * the bid. A ciphertext that does not deserialize opens nothing.
 */
export async function opensCommitment(bids: readonly SubmittedBid[]): Promise<(ciphertext: Hex, commitment: Hex) => boolean> {
  const recomputed = new Map<Hex, Hex | undefined>()
  await Promise.all(
    bids
      .flatMap((bid) => bid.ciphertexts)
      .map(async (ciphertext) => {
        recomputed.set(ciphertext, await computeCiphertextCommitment(hexToBytes(ciphertext), PRESET).then(bytesToHex, () => undefined))
      }),
  )
  return (ciphertext, commitment) => recomputed.get(ciphertext)?.toLowerCase() === commitment.toLowerCase()
}
