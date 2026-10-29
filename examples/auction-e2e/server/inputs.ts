// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { computeCiphertextCommitment } from '@interfold/sdk'
import { type Address, bytesToHex, hexToBytes, zeroAddress, type Hex } from 'viem'
import {
  type AuctionType,
  MASK_VERSION,
  MIN_BIDDERS,
  PRESET,
  type SubmittedBid,
  type SubmittedMask,
  auctionConfigInput,
  checkMasks,
  isProviderType,
  selectBids,
} from '@interfold/auction'

/** The zero commitment of the configuration input. */
const ZERO_COMMITMENT = `0x${'00'.repeat(32)}`

/**
 * The inputs of a round in the shape of the program runner request. The four lists have one entry
 * per input, in leaf order; `ciphertexts` holds `[bytes, leaf index]`.
 *
 * Index 0 is the configuration: a zero commitment, the zero address and version 0. Every other
 * input is one ciphertext: its commitment, the sender (the runner's "slot") and the version (the
 * runner's "parent"). A bidder's ciphertext has the bid version. A mask has the provider as sender
 * and `MASK_VERSION`. The program turns the slot and the version into the 25-byte metadata of the leaf.
 */
export interface ProgramInputs {
  ciphertexts: Array<[string, number]>
  commitments: string[]
  slots: string[]
  parents: number[]
}

/** The mask providers of a mask-provider auction and the masks they sent. Both are empty for the other types. */
export interface MaskInputs {
  providers: readonly Address[]
  masks: readonly SubmittedMask[]
}

const NO_MASKS: MaskInputs = { providers: [], masks: [] }

/**
 * Every published input of an auction in leaf order: the configuration at leaf 0 (it names the mask
 * providers of a mask-provider auction), then the masks, then the ciphertexts of every bid, whether or not
 * the program will count it. The input root covers all leaves, so the program needs all of them.
 * Events do not arrive in leaf order, so this sorts them.
 *
 * Throws if the leaves are not 1, 2, 3, ... without a gap, which means an event is missing.
 */
export function auctionInputs(
  type: AuctionType,
  bids: readonly SubmittedBid[],
  { providers, masks }: MaskInputs = NO_MASKS,
): ProgramInputs {
  const inputs: ProgramInputs = {
    ciphertexts: [[auctionConfigInput(type, providers), 0]],
    commitments: [ZERO_COMMITMENT],
    slots: [zeroAddress],
    parents: [0],
  }
  for (const mask of [...masks].sort((a, b) => a.index - b.index)) {
    if (mask.index !== inputs.ciphertexts.length) {
      throw new Error(`Leaf ${inputs.ciphertexts.length} has no mask event; the next one starts at leaf ${mask.index}`)
    }
    inputs.ciphertexts.push([mask.ciphertext, mask.index])
    inputs.commitments.push(mask.commitment)
    inputs.slots.push(mask.provider)
    inputs.parents.push(MASK_VERSION)
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
 * The `opens` function of `selectBids` and `checkMasks` for these ciphertexts. It recomputes the SAFE
 * commitment of every ciphertext once, with the same function the proofs use, and compares it with
 * the published commitment. A ciphertext that does not deserialize opens nothing.
 */
export async function opensCommitment(ciphertexts: readonly Hex[]): Promise<(ciphertext: Hex, commitment: Hex) => boolean> {
  const recomputed = new Map<Hex, Hex | undefined>()
  await Promise.all(
    [...new Set(ciphertexts)].map(async (ciphertext) => {
      recomputed.set(ciphertext, await computeCiphertextCommitment(hexToBytes(ciphertext), PRESET).then(bytesToHex, () => undefined))
    }),
  )
  return (ciphertext, commitment) => recomputed.get(ciphertext)?.toLowerCase() === commitment.toLowerCase()
}

/** What the server does with an auction when its input window has closed. `counted` is the number of bidders that count. */
export type RunPlan = { kind: 'run'; inputs: ProgramInputs; counted: number } | { kind: 'skip'; reason: string; counted: number }

/**
 * Decide whether an auction has a computation to run, and build its inputs if it has. The program
 * needs {@link MIN_BIDDERS} bidders whose bids open their commitments. A mask-provider auction also needs
 * every mask, each one opening its commitment: the program stops without one, so the server does not
 * start it. `opens` is the function of {@link opensCommitment}.
 *
 * Throws if an event is missing (see {@link auctionInputs}).
 */
export function planRun(
  type: AuctionType,
  bids: readonly SubmittedBid[],
  maskInputs: MaskInputs,
  opens: (ciphertext: Hex, commitment: Hex) => boolean,
): RunPlan {
  const inputs = auctionInputs(type, bids, maskInputs)
  const counted = selectBids(bids, opens).length
  if (isProviderType(type)) {
    const { complete, missing, invalid } = checkMasks(maskInputs.masks, maskInputs.providers, opens)
    if (!complete) {
      const parts = [
        missing.length > 0 ? `no mask from ${missing.join(', ')}` : '',
        invalid.length > 0 ? `a mask that does not open its commitment from ${invalid.join(', ')}` : '',
      ].filter(Boolean)
      return { kind: 'skip', counted, reason: `the masks are not complete: ${parts.join('; ')}` }
    }
  }
  if (counted < MIN_BIDDERS) {
    return {
      kind: 'skip',
      counted,
      reason: `${counted} bidder(s) with a bid that opens its commitments, an auction needs ${MIN_BIDDERS}`,
    }
  }
  return { kind: 'run', inputs, counted }
}
