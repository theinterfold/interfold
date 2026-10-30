// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * First-price sealed-bid auction on the live Sepolia deploy, through `@interfold/auction-first-price`.
 * Two bidders bid. The highest bid wins and the winner pays its own bid. Run: `pnpm example:first-price`.
 * Spends Sepolia gas: see examples/README.md.
 */

import { evenPrices } from '@interfold/auction-core'
import * as firstPrice from '@interfold/auction-first-price'
import { createBidProver } from '@interfold/auction-first-price/prover'
import { runAuction, runExample } from './lib/auction'
import { loadEnv } from './lib/config'

await runExample(async () => {
  const env = loadEnv()
  const prices = evenPrices(100n, 100n, 16)
  await runAuction(
    {
      kit: firstPrice,
      createBidProver,
      prices,
      customParams: firstPrice.encodeParams(prices, 'First-price example'),
      // Bidder 2 bids higher, so it wins and pays its own bid: step 9.
      bids: [5, 9],
    },
    env,
  )
})
