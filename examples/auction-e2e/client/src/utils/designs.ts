// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * The three design packages, by auction type. The contract stores the type of an auction, so the
 * app picks the package to read the label, decode the result or prove a bid at run time.
 */
import type { Address, Hex } from 'viem'
import { zeroAddress } from 'viem'
import { AuctionType, type AuctionDesign, type PriceList } from '@interfold/auction-core'
import type { BidProver } from '@interfold/auction-core/prover'
import * as firstPrice from '@interfold/auction-first-price'
import { createBidProver as createFirstPriceProver } from '@interfold/auction-first-price/prover'
import * as providerSecondPrice from '@interfold/auction-provider-second-price'
import { createBidProver as createProviderProver } from '@interfold/auction-provider-second-price/prover'
import * as qnrSecondPrice from '@interfold/auction-qnr-second-price'
import { createBidProver as createQnrProver } from '@interfold/auction-qnr-second-price/prover'

/** The root of the design package of each auction type. */
export const DESIGNS = {
  [AuctionType.FirstPrice]: firstPrice,
  [AuctionType.ProviderSecondPrice]: providerSecondPrice,
  [AuctionType.QnrSecondPrice]: qnrSecondPrice,
} satisfies Record<AuctionType, { design: AuctionDesign; decodeResult: unknown; expectedResult: unknown }>

/** The description of the design of `type`: label, roles, what it reveals and whom you trust. */
export const designOf = (type: AuctionType): AuctionDesign => DESIGNS[type].design

/** Whether an auction of `type` names mask providers. */
export const hasProviders = (type: AuctionType): boolean => designOf(type).providers === 'required'

/** Start the prover of the design of `type`. The caller calls `destroy()` on it. */
export function createProver(type: AuctionType): Promise<BidProver> {
  if (type === AuctionType.ProviderSecondPrice) return createProviderProver()
  return type === AuctionType.FirstPrice ? createFirstPriceProver() : createQnrProver()
}

/** The `customParams` of an auction request, from the package of the design of `type`. */
export function encodeParams(
  type: AuctionType,
  prices: PriceList,
  title: string,
  gate: Address = zeroAddress,
  gateConfig: Hex = '0x',
  providers: readonly Address[] = [],
): Hex {
  if (type === AuctionType.ProviderSecondPrice) return providerSecondPrice.encodeParams(prices, title, providers, gate, gateConfig)
  return DESIGNS[type].encodeParams(prices, title, gate, gateConfig)
}
