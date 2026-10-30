// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * The prover of the first-price auction. It makes the bid proof of `auction_bid3`: the roles 0 and 1
 * (the thermometers) go through `auction_bid_pair`, and the mask of the role 2 goes to the final
 * circuit with its encryption proof.
 *
 * This entry loads `@aztec-foundation/bb.js` and the circuits of this design. Import it only where
 * proofs are made. The root of the package has no proving backend.
 *
 * @packageDocumentation
 */
import { type BidProver, type BidTreeSpec, ProvingEngine, proofToFields } from '@interfold/auction-core/prover'
import type { CompiledCircuit } from '@noir-lang/noir_js'
import bid3CircuitJson from '../circuits/auction_bid3.json'
import { TYPE } from './index'

export type { BidProver, BidStep, PreparedBid } from '@interfold/auction-core/prover'

const spec: BidTreeSpec = {
  type: TYPE,
  bidCircuit: bid3CircuitJson as CompiledCircuit,
  async finalInputs({ commonInputs, encryptions, udeKey }) {
    const mask = encryptions[2]
    return {
      ...commonInputs,
      user_data_encryption_verification_key: udeKey.vkAsFields,
      mask_proof: proofToFields(mask.wrapper.proof),
      mask_public_inputs: mask.wrapper.publicInputs,
    }
  },
}

/**
 * Start a prover for first-price bids. Loading the SRS dominates a small proof, so keep one prover
 * open for all the bids of a bidder.
 *
 * @returns A prover. Call `destroy()` when done.
 */
export async function createBidProver(): Promise<BidProver> {
  const engine = await ProvingEngine.create()
  return {
    prove: (bid, levels, committeeKey, bidder, onStep) => engine.proveBid(spec, bid, levels, committeeKey, bidder, onStep),
    destroy: () => engine.destroy(),
  }
}
