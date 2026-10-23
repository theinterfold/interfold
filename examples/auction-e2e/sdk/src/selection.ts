// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { Address, Hex } from 'viem'

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
 * `opens(ciphertext, commitment)` recomputes the SAFE commitment of the ciphertext bytes and compares
 * it with `commitment`.
 */
export function selectBids(bids: readonly SubmittedBid[], opens: (ciphertext: Hex, commitment: Hex) => boolean): SelectedBid[] {
  const latest = new Map<string, SubmittedBid>()
  for (const bid of bids) {
    if (bid.ciphertexts.length === 0 || bid.ciphertexts.length !== bid.commitments.length) continue
    if (!bid.ciphertexts.every((ciphertext, role) => opens(ciphertext, bid.commitments[role]))) continue
    const key = bid.bidder.toLowerCase()
    const chosen = latest.get(key)
    if (chosen === undefined || chosen.version < bid.version) latest.set(key, bid)
  }
  return [...latest.values()].sort((a, b) => a.firstIndex - b.firstIndex).map((bid, position) => ({ ...bid, position }))
}
