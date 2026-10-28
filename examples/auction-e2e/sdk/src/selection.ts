// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { Address, Hex } from 'viem'
import { MASK_VERSION } from './layout'

/** One `BidSubmitted` event: a bid of one bidder, with its ciphertexts in role order. */
export interface SubmittedBid {
  bidder: Address
  /** The version of the bid: 1 for the first bid of the bidder, 2 for its first update, and so on. */
  version: number
  /** The leaf index of the first ciphertext. The others follow it in role order. */
  firstIndex: number
  ciphertexts: Hex[]
  commitments: Hex[]
}

/** A bid that counts. `position` is its place among the counted bids, in leaf order. */
export interface SelectedBid extends SubmittedBid {
  position: number
}

/**
 * Which bids the auction computes over. This is the rule of `select_bids` in `program/src/lib.rs`.
 *
 * For each bidder it takes the bid with the highest version in which every ciphertext opens its
 * commitment. A bidder with no such bid is dropped whole, and a bid is never taken in part. The
 * result is in leaf order, so `position` is the bidder position of the computation.
 *
 * An entry with the version `MASK_VERSION` is a mask, not a bid, and is skipped: `checkMasks` reads
 * the masks.
 *
 * `opens(ciphertext, commitment)` recomputes the SAFE commitment of the ciphertext bytes and compares
 * it with `commitment`.
 */
export function selectBids(bids: readonly SubmittedBid[], opens: (ciphertext: Hex, commitment: Hex) => boolean): SelectedBid[] {
  const latest = new Map<string, SubmittedBid>()
  for (const bid of bids) {
    if (bid.version === MASK_VERSION) continue
    if (bid.ciphertexts.length === 0 || bid.ciphertexts.length !== bid.commitments.length) continue
    if (!bid.ciphertexts.every((ciphertext, role) => opens(ciphertext, bid.commitments[role]))) continue
    const key = bid.bidder.toLowerCase()
    const chosen = latest.get(key)
    if (chosen === undefined || chosen.version < bid.version) latest.set(key, bid)
  }
  return [...latest.values()].sort((a, b) => a.firstIndex - b.firstIndex).map((bid, position) => ({ ...bid, position }))
}

/** One `MaskSubmitted` event: the mask ciphertext of a provider of a `ProviderSecondPrice` auction. */
export interface SubmittedMask {
  provider: Address
  /** The leaf index of the mask. The masks are the leaves 1 to k, in submission order. */
  index: number
  ciphertext: Hex
  commitment: Hex
}

/** What `checkMasks` finds. The lists hold the providers as the auction names them, in that order. */
export interface MaskStatus {
  /** Whether every provider sent a mask that opens its commitment. Only then can the program run. */
  complete: boolean
  /** The providers with no mask. */
  missing: Address[]
  /** The providers whose mask does not open its commitment. */
  invalid: Address[]
}

/**
 * Whether the auction has all its masks. The program needs every mask of the configuration: one
 * mask that does not open its commitment, or a missing one, means the auction cannot run (see
 * `select_bids`, which then selects only the configuration). A mask from an address that is no
 * provider is ignored. If a provider has several masks, the one with the lowest leaf counts.
 *
 * `opens(ciphertext, commitment)` is the same check as for `selectBids`.
 */
export function checkMasks(
  masks: readonly SubmittedMask[],
  providers: readonly Address[],
  opens: (ciphertext: Hex, commitment: Hex) => boolean,
): MaskStatus {
  const first = new Map<string, SubmittedMask>()
  for (const mask of masks) {
    const key = mask.provider.toLowerCase()
    const chosen = first.get(key)
    if (chosen === undefined || mask.index < chosen.index) first.set(key, mask)
  }
  const missing: Address[] = []
  const invalid: Address[] = []
  for (const provider of providers) {
    const mask = first.get(provider.toLowerCase())
    if (mask === undefined) missing.push(provider)
    else if (!opens(mask.ciphertext, mask.commitment)) invalid.push(provider)
  }
  return { complete: missing.length === 0 && invalid.length === 0, missing, invalid }
}
