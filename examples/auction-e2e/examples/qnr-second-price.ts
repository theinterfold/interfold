// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * Second-price sealed-bid auction without mask providers on the live Sepolia deploy, through
 * `@interfold/auction-qnr-second-price`. The bidders add shares to build the mask themselves, so
 * the auction needs no provider. The highest bid wins and the winner pays the second-highest bid.
 * Run: `pnpm example:qnr-second-price`. Spends Sepolia gas: see examples/README.md.
 */

import { evenPrices } from '@interfold/auction-core'
import * as qnrSecondPrice from '@interfold/auction-qnr-second-price'
import { createBidProver } from '@interfold/auction-qnr-second-price/prover'
import { runAuction, runExample } from './lib/auction'
import { loadEnv } from './lib/config'

await runExample(async () => {
  const env = loadEnv()
  const prices = evenPrices(100n, 100n, 16)
  await runAuction(
    {
      kit: qnrSecondPrice,
      createBidProver,
      prices,
      customParams: qnrSecondPrice.encodeParams(prices, 'QNR second-price example'),
      // Bidder 2 bids higher, so it wins and pays the bid of bidder 1: step 5.
      bids: [5, 9],
    },
    env,
  )
})
