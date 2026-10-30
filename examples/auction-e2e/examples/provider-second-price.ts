// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * Second-price sealed-bid auction with mask providers on the live Sepolia deploy, through
 * `@interfold/auction-provider-second-price`. The live demo server is the one mask provider; the
 * bidders bid after its mask is in. The highest bid wins and the winner pays the second-highest
 * bid. Run: `pnpm example:provider-second-price`. Spends Sepolia gas: see examples/README.md.
 */

import { evenPrices } from '@interfold/auction-core'
import * as providerSecondPrice from '@interfold/auction-provider-second-price'
import { createBidProver } from '@interfold/auction-provider-second-price/prover'
import { runAuction, runExample } from './lib/auction'
import { DEPLOYMENT, loadEnv } from './lib/config'

await runExample(async () => {
  const env = loadEnv()
  const prices = evenPrices(100n, 100n, 16)
  const providers = [DEPLOYMENT.serverProvider]
  await runAuction(
    {
      kit: providerSecondPrice,
      createBidProver,
      prices,
      customParams: providerSecondPrice.encodeParams(prices, 'Provider second-price example', providers),
      providers: { addresses: providers, checkMasks: providerSecondPrice.checkMasks },
      // Bidder 2 bids higher, so it wins and pays the bid of bidder 1: step 5.
      bids: [5, 9],
    },
    env,
  )
})
