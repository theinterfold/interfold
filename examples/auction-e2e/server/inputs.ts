// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { type AuctionType, auctionConfigInput, rolesFor } from '../shared/layout'

/** A `BidSubmitted` event: one ciphertext of a bidder. */
export interface SubmittedCiphertext {
  bidder: string
  role: number
  ciphertext: string
}

/** A `BidLinked` event: the bidder has all ciphertexts of its auction type in the tree from `firstIndex` on. */
export interface LinkedBid {
  bidder: string
  firstIndex: bigint
}

/**
 * The program inputs of an auction as `[bytes, leaf index]` pairs in leaf order: the configuration
 * at leaf 0, then the ciphertexts of each linked bidder, one per role of the auction type
 * (`rolesFor`), at `firstIndex + role position`. Only linked bidders are included. The program
 * server needs leaf order, and event order is not guaranteed.
 */
export function auctionInputs(
  type: AuctionType,
  submitted: readonly SubmittedCiphertext[],
  linked: readonly LinkedBid[],
): Array<[string, number]> {
  const ciphertexts = new Map<string, string>()
  for (const { bidder, role, ciphertext } of submitted) ciphertexts.set(`${bidder}:${role}`, ciphertext)
  const inputs: Array<[string, number]> = [[auctionConfigInput(type), 0]]
  for (const { bidder, firstIndex } of linked) {
    rolesFor(type).forEach((role, position) => {
      const ciphertext = ciphertexts.get(`${bidder}:${role}`)
      if (ciphertext === undefined) throw new Error(`No ciphertext for role ${role} of linked bidder ${bidder}`)
      inputs.push([ciphertext, Number(firstIndex) + position])
    })
  }
  return inputs.sort((a, b) => a[1] - b[1])
}
