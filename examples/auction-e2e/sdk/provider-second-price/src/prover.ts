// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * The prover of the second-price auction with mask providers. A bidder proves a bid of 2
 * ciphertexts `[ge, gt]` with `auction_bid2`. A mask provider proves its mask with `auction_mask`.
 *
 * This entry loads `@aztec-foundation/bb.js` and the circuits of this design. Import it only where
 * proofs are made. The root of the package has no proving backend.
 *
 * @packageDocumentation
 */
import { type BidProver, type BidTreeSpec, ProvingEngine, keyOf, proofToFields } from '@interfold/auction-core/prover'
import type { CompiledCircuit, InputMap } from '@noir-lang/noir_js'
import bid2CircuitJson from '../circuits/auction_bid2.json'
import maskCircuitJson from '../circuits/auction_mask.json'
import type { Address, Hex } from 'viem'
import { DEGREE, PLAINTEXT_MODULUS, PRESET, toHex } from '@interfold/auction-core'
import { openLbfvKeyEnvelope } from '@interfold/sdk'
import { TYPE } from './index'

export type { BidProver, BidStep, PreparedBid } from '@interfold/auction-core/prover'

const spec: BidTreeSpec = {
  type: TYPE,
  bidCircuit: bid2CircuitJson as CompiledCircuit,
  async finalInputs({ commonInputs, shared }) {
    return { ...commonInputs, ct0_chain: shared.ct0_chain, ct1_chain: shared.ct1_chain }
  },
}
const maskCircuit = maskCircuitJson as CompiledCircuit

/** One mask of a provider, encrypted and proven, ready for `AuctionProgram.publishInput`. */
export interface PreparedMask {
  /** The one ciphertext: 128 SIMD slots, all nonzero mod 257. */
  ciphertext: Hex
  /** Its ciphertext commitment (bytes32). */
  commitment: Hex
  /** The mask proof, the only proof that goes on chain. */
  proof: Hex
  /** The proof's public output: the committee key commitment. For display. */
  pkCommitment: Hex
  /** The proof's public output: the VK anchor. For display. */
  vkAnchor: Hex
}

/** A step of the proof of a mask, for a progress display. */
export type MaskStep = { kind: 'encrypt' } | { kind: 'encryption-proof' } | { kind: 'mask-proof' }

/** A prover for bids and for the masks of a provider. Both use the same Barretenberg instance. */
export interface ProviderProver extends BidProver {
  /**
   * Encrypt the mask of a provider to the committee key and prove it valid, with one proof.
   *
   * The plaintext has 128 SIMD slots, each drawn uniform in 1 to 256 with `crypto.getRandomValues`.
   * The program multiplies the output of the auction by the masks of all providers, so a zero slot
   * would erase a result. The proofs are Interfold's user-data encryption proof (the ciphertext
   * encrypts `k1` under the committee key), and `auction_mask`, which verifies it and proves that
   * `k1` is the plaintext of 128 slots that are all nonzero mod 257. The mask proof is the only
   * proof published. It binds `provider`, the address that sends `publishInput`.
   *
   * @param committeeKey The public key of the committee of the E3.
   * @param provider The address that will send the mask.
   * @param onStep Called before each step.
   * @throws When the committee key is not an l-BFV key, or a proof fails.
   */
  proveMask(committeeKey: Uint8Array, provider: Address, onStep?: (step: MaskStep) => void): Promise<PreparedMask>
}

/**
 * The slots of a provider mask: uniform in `1..=t - 1`. The mask circuit proves that no slot is 0,
 * and an honest provider has no reason to leave a slot guessable. With `t = 257` one random byte
 * plus 1 is uniform in `1..=256`, so no sample is rejected.
 */
function maskSlots(): BigUint64Array {
  if (PLAINTEXT_MODULUS !== 257) throw new Error('The mask slots are sampled for the plaintext modulus 257')
  const bytes = new Uint8Array(DEGREE)
  globalThis.crypto.getRandomValues(bytes)
  return BigUint64Array.from(bytes, (byte) => BigInt(byte) + 1n)
}

/**
 * Start a prover for bids and masks. Loading the SRS dominates a small proof, so keep one prover
 * open for all the proofs of a participant.
 *
 * @returns A prover. Call `destroy()` when done.
 */
export async function createBidProver(): Promise<ProviderProver> {
  const engine = await ProvingEngine.create()
  return {
    prove: (bid, levels, committeeKey, bidder, onStep) => engine.proveBid(spec, bid, levels, committeeKey, bidder, onStep),
    destroy: () => engine.destroy(),
    async proveMask(committeeKey, provider, onStep) {
      onStep?.({ kind: 'encrypt' })
      const slots = maskSlots()
      const encrypted = await engine.encrypt(slots, committeeKey)
      onStep?.({ kind: 'encryption-proof' })
      const { ciphertext, commitment, k1, wrapper } = await engine.proveEncrypted(encrypted)
      const udeKey = await keyOf(wrapper)

      onStep?.({ kind: 'mask-proof' })
      const opening = await openLbfvKeyEnvelope(committeeKey, PRESET)
      const { proof, pkCommitment, vkAnchor } = await engine.proveFinal(
        maskCircuit,
        {
          user_data_encryption_verification_key: udeKey.vkAsFields,
          user_data_encryption_proof: proofToFields(wrapper.proof),
          user_data_encryption_public_inputs: wrapper.publicInputs,
          user_data_encryption_key_hash: udeKey.vkHash,
          ct_commitment: commitment,
          provider: BigInt(provider).toString(),
          public_key_row_commitments: opening.publicKeyRows.map(toHex),
          relinearization_key_commitment: toHex(opening.relinearizationKey),
          k1: { coefficients: k1.coefficients },
          slot_values: Array.from(slots, (slot) => slot.toString()),
        } as InputMap,
        committeeKey,
      )
      return { ciphertext, commitment, proof, pkCommitment, vkAnchor }
    },
  }
}
