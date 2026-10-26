// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { computeCiphertextCommitment } from '@interfold/sdk'
import { PRESET, roundConfigInput, type RoundParams } from '@interfold/private-round'
import { bytesToHex, hexToBytes, zeroAddress, type Address, type Hex } from 'viem'

/** The zero commitment of the configuration input. */
const ZERO_COMMITMENT = `0x${'00'.repeat(32)}`

/** The ciphertexts of a bid: role 0 is the bid, role 1 is the mask. */
export const CIPHERTEXTS_PER_BID = 2

/** The fewest counted bidders for which the program runs. A round with none has no output. */
export const MIN_BIDDERS = 1

/** One `BidSubmitted` event: a bid of one bidder. It is two ciphertexts and two consecutive leaves. */
export interface SubmittedBid {
  bidder: Address
  /** The version of the bid: 1 for the first bid of the bidder, 2 for its first update, and so on. */
  version: number
  /** The leaf index of the bid ciphertext (role 0). The mask ciphertext (role 1) is the next leaf. Leaf 0 is the configuration. */
  firstLeaf: number
  /** The bid ciphertext and the mask ciphertext, in role order. */
  ciphertexts: readonly Hex[]
  /** The SAFE commitment of each ciphertext, in role order. */
  ctCommitments: readonly Hex[]
}

/**
 * The inputs of a round in the shape of the program runner request. The four lists have one entry
 * per input, in leaf order; `ciphertexts` holds `[bytes, leaf index]`.
 *
 * Index 0 is the configuration: a zero commitment, the zero address and version 0. Every other
 * input is one ciphertext of a bid: its commitment, the bidder (the runner's "slot") and the bid
 * version (the runner's "parent"). The two ciphertexts of a bid have the same slot and the same
 * version, so the program sees them as one run of equal metadata.
 */
export interface ProgramInputs {
  ciphertexts: Array<[string, number]>
  commitments: string[]
  slots: string[]
  parents: number[]
}

/**
 * Every published input of a round in leaf order: the configuration at leaf 0, then the two
 * ciphertexts of every bid, whether or not the program will count it. The input root covers all
 * leaves, so the program needs all of them. Events do not arrive in leaf order, so this sorts them.
 *
 * `params` are the public parameters of the round (`levels`, `reserveStep`, `lots`, `minLots`); they
 * give the configuration input.
 *
 * Throws if the leaves are not 1, 2, 3, ... without a gap, which means an event is missing.
 */
export function roundInputs(params: RoundParams, bids: readonly SubmittedBid[]): ProgramInputs {
  const inputs: ProgramInputs = {
    ciphertexts: [[roundConfigInput(params), 0]],
    commitments: [ZERO_COMMITMENT],
    slots: [zeroAddress],
    parents: [0],
  }
  for (const bid of [...bids].sort((a, b) => a.firstLeaf - b.firstLeaf)) {
    if (bid.ciphertexts.length !== CIPHERTEXTS_PER_BID || bid.ctCommitments.length !== CIPHERTEXTS_PER_BID) {
      throw new Error(
        `Bid ${bid.version} of ${bid.bidder} has ${bid.ciphertexts.length} ciphertexts and ${bid.ctCommitments.length} commitments, a bid has ${CIPHERTEXTS_PER_BID}`,
      )
    }
    bid.ciphertexts.forEach((ciphertext, role) => {
      if (bid.firstLeaf + role !== inputs.ciphertexts.length) {
        throw new Error(`Leaf ${inputs.ciphertexts.length} has no bid event; the next one starts at leaf ${bid.firstLeaf + role}`)
      }
      inputs.ciphertexts.push([ciphertext, bid.firstLeaf + role])
      inputs.commitments.push(bid.ctCommitments[role])
      inputs.slots.push(bid.bidder)
      inputs.parents.push(bid.version)
    })
  }
  return inputs
}

/**
 * The bids that the program counts. This is the rule of `select_bids` in `program/src/lib.rs`: the
 * program reads the leaves as runs of equal metadata (bidder and version), and a run counts only if
 * both of its ciphertexts open their commitments. For each bidder the run with the highest version
 * wins. A bidder with no such run is dropped whole, and a bid is never taken in part. The result is
 * in leaf order.
 *
 * `opens(ciphertext, commitment)` recomputes the SAFE commitment of the ciphertext bytes and
 * compares it with `commitment`.
 */
export function selectBids(bids: readonly SubmittedBid[], opens: (ciphertext: Hex, commitment: Hex) => boolean): SubmittedBid[] {
  const latest = new Map<string, SubmittedBid>()
  for (const bid of bids) {
    if (bid.ciphertexts.length !== CIPHERTEXTS_PER_BID || bid.ctCommitments.length !== CIPHERTEXTS_PER_BID) continue
    if (!bid.ciphertexts.every((ciphertext, role) => opens(ciphertext, bid.ctCommitments[role]))) continue
    const key = bid.bidder.toLowerCase()
    const chosen = latest.get(key)
    if (!chosen || chosen.version < bid.version) latest.set(key, bid)
  }
  return [...latest.values()].sort((a, b) => a.firstLeaf - b.firstLeaf)
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
