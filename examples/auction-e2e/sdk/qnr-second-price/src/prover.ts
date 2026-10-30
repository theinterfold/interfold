// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * The prover of the second-price auction with no mask providers. A bid has 4 ciphertexts
 * `[ge, gt, share, share]`. The roles 0 and 1 go through `auction_bid_pair`, the two shares go
 * through `auction_bid_shares`, and `auction_bid4` verifies both.
 *
 * This entry loads `@aztec-foundation/bb.js` and the circuits of this design. Import it only where
 * proofs are made. The root of the package has no proving backend.
 *
 * @packageDocumentation
 */
import { type BidProver, type BidTreeSpec, ProvingEngine, keyOf, proofToFields } from '@interfold/auction-core/prover'
import type { CompiledCircuit } from '@noir-lang/noir_js'
import bid4CircuitJson from '../circuits/auction_bid4.json'
import sharesCircuitJson from '../circuits/auction_bid_shares.json'
import { TYPE } from './index'

export type { BidProver, BidStep, PreparedBid } from '@interfold/auction-core/prover'

const spec: BidTreeSpec = {
  type: TYPE,
  bidCircuit: bid4CircuitJson as CompiledCircuit,
  async finalInputs({ engine, commonInputs, encryptions, udeKey, shared, wrapperInputs, step }) {
    const [, , first, second] = encryptions
    step({ kind: 'shares-proof' })
    const shares = await engine.proveInner(sharesCircuitJson as CompiledCircuit, {
      ...wrapperInputs([first, second]),
      ct_commitments: [first.commitment, second.commitment],
      ...shared,
      user_data_encryption_key_hash: udeKey.vkHash,
    })
    const sharesKey = await keyOf(shares)
    return {
      ...commonInputs,
      ct0_chain: shared.ct0_chain,
      ct1_chain: shared.ct1_chain,
      shares_verification_key: sharesKey.vkAsFields,
      shares_proof: proofToFields(shares.proof),
      shares_key_hash: sharesKey.vkHash,
    }
  },
}

/**
 * Start a prover for no-provider second-price bids. Loading the SRS dominates a small proof, so keep
 * one prover open for all the bids of a bidder.
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
