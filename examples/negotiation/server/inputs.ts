// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { computeCiphertextCommitment } from '@interfold/sdk'
import { bytesToHex, hexToBytes, stringToHex, zeroAddress, type Address, type Hex } from 'viem'

/** The preset name that the SDK and the program use. */
export const PRESET = 'INSECURE_THRESHOLD_SIMD' as const

/** Input 0 of a negotiation. `NegotiationProgram.CONFIG_DOMAIN` and `CONFIG_DOMAIN` in `program/src/lib.rs` are the same bytes. */
export const CONFIG_DOMAIN = 'interfold-negotiation-config-v1'

/** The zero commitment of the configuration input. */
const ZERO_COMMITMENT = `0x${'00'.repeat(32)}`

/** The ciphertexts of one offer. `OFFER_CIPHERTEXTS` in `sdk/src/layout.ts`. */
export const OFFER_CIPHERTEXTS = 3

/** The roles of a negotiation. The seller is 0 and the buyer is 1. */
export const ROLES = [0, 1] as const

/** Input 0 of a negotiation: the domain bytes. */
export function negotiationConfigInput(): Hex {
  return stringToHex(CONFIG_DOMAIN)
}

/** One `OfferSubmitted` event: the three ciphertexts of one party. It inserts three leaves. */
export interface SubmittedOffer {
  party: Address
  /** 0 for the seller, 1 for the buyer. */
  role: number
  ciphertexts: readonly Hex[]
  commitments: readonly Hex[]
}

/**
 * The inputs of a negotiation in the shape of the program runner request. The four lists have one
 * entry per input, in leaf order; `ciphertexts` holds `[bytes, leaf index]`.
 *
 * Index 0 is the configuration: a zero commitment, the zero address and the parent 0. Every other
 * input is one ciphertext of an offer: its commitment, the party (the runner's "slot") and
 * `role * 256 + index` (the runner's "parent"). The runner packs the slot and the parent into the
 * 25-byte metadata of the leaf: `party (20) || uint40(role * 256 + index)`.
 */
export interface ProgramInputs {
  ciphertexts: Array<[string, number]>
  commitments: string[]
  slots: string[]
  parents: number[]
}

/**
 * Every published input of a negotiation in leaf order: the configuration at leaf 0, then the three
 * ciphertexts of every offer in the order of the events (block, then log index). The input root
 * covers all leaves, so the program needs all of them, whether or not it will use them.
 *
 * Throws if an offer has no 3 ciphertexts and 3 commitments, or has a role that is not 0 or 1.
 */
export function negotiationInputs(offers: readonly SubmittedOffer[]): ProgramInputs {
  const inputs: ProgramInputs = {
    ciphertexts: [[negotiationConfigInput(), 0]],
    commitments: [ZERO_COMMITMENT],
    slots: [zeroAddress],
    parents: [0],
  }
  for (const offer of offers) {
    if (!ROLES.some((role) => role === offer.role)) throw new Error(`Offer of ${offer.party} has the role ${offer.role}`)
    if (offer.ciphertexts.length !== OFFER_CIPHERTEXTS || offer.commitments.length !== OFFER_CIPHERTEXTS) {
      throw new Error(`Offer of ${offer.party} has ${offer.ciphertexts.length} ciphertext(s) and ${offer.commitments.length} commitment(s)`)
    }
    offer.ciphertexts.forEach((ciphertext, index) => {
      inputs.ciphertexts.push([ciphertext, inputs.ciphertexts.length])
      inputs.commitments.push(offer.commitments[index])
      inputs.slots.push(offer.party)
      inputs.parents.push(offer.role * 256 + index)
    })
  }
  return inputs
}

/**
 * The roles that have a complete offer: one whose three ciphertexts all open their commitments.
 * This is the rule of the program, which leaves out a ciphertext that does not open. The program
 * has an output only if both roles are in the result. `opens(ciphertext, commitment)` recomputes
 * the SAFE commitment of the bytes and compares it with `commitment`.
 */
export function completeRoles(offers: readonly SubmittedOffer[], opens: (ciphertext: Hex, commitment: Hex) => boolean): Set<number> {
  const complete = new Set<number>()
  for (const offer of offers) {
    if (offer.ciphertexts.every((ciphertext, index) => opens(ciphertext, offer.commitments[index]))) complete.add(offer.role)
  }
  return complete
}

/**
 * The `opens` function of `completeRoles` for these offers. It recomputes the SAFE commitment of
 * every ciphertext once, with the same function the offer proof uses, and compares it with the
 * commitment of the offer. A ciphertext that does not deserialize opens nothing.
 */
export async function opensCommitment(offers: readonly SubmittedOffer[]): Promise<(ciphertext: Hex, commitment: Hex) => boolean> {
  const recomputed = new Map<Hex, Hex | undefined>()
  await Promise.all(
    offers
      .flatMap(({ ciphertexts }) => ciphertexts)
      .map(async (ciphertext) => {
        recomputed.set(ciphertext, await computeCiphertextCommitment(hexToBytes(ciphertext), PRESET).then(bytesToHex, () => undefined))
      }),
  )
  return (ciphertext, commitment) => recomputed.get(ciphertext)?.toLowerCase() === commitment.toLowerCase()
}
