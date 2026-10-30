// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { encodeBidInput } from '@interfold/auction-core'
import type { Address, Hex } from 'viem'

/** One `MaskSubmitted` event: the mask ciphertext of a provider of a second-price auction with mask providers. */
export interface SubmittedMask {
  /** The address of the mask provider. */
  provider: Address
  /** The leaf index of the mask. The masks are the leaves 1 to k, in submission order. */
  index: number
  /** The ciphertext bytes of the mask. */
  ciphertext: Hex
  /** The commitment of the ciphertext. */
  commitment: Hex
}

/** What {@link checkMasks} finds. The lists hold the providers as the auction names them, in that order. */
export interface MaskStatus {
  /** Whether every provider sent a mask that opens its commitment. Only then can the program run. */
  complete: boolean
  /** The providers with no mask. */
  missing: Address[]
  /** The providers whose mask does not open its commitment. */
  invalid: Address[]
}

/**
 * Encode the `data` of `AuctionProgram.publishInput` for the mask of a provider: the encoding of
 * `encodeBidInput` with the provider as `bidder`, one ciphertext and one commitment, and an empty
 * `gateProof` and `signature`.
 *
 * @param input The provider address and the fields of a prepared mask.
 */
export function encodeMaskInput(input: { provider: Address; ciphertext: Hex; commitment: Hex; proof: Hex }): Hex {
  return encodeBidInput({
    bidder: input.provider,
    ciphertexts: [input.ciphertext],
    commitments: [input.commitment],
    proof: input.proof,
    gateProof: '0x',
    signature: '0x',
  })
}

/**
 * Find out whether the auction has all its masks. The program needs every mask of the configuration:
 * one mask that does not open its commitment, or a missing one, means the auction cannot run (see
 * `select_bids`, which then selects only the configuration). A mask from an address that is no
 * provider is ignored. If a provider has several masks, the one with the lowest leaf counts.
 *
 * @param masks Every `MaskSubmitted` event of the auction.
 * @param providers The mask providers of the auction, in the order of the request.
 * @param opens Recomputes the SAFE commitment of the ciphertext bytes and compares it with `commitment`. The same check as for `selectBids`.
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
