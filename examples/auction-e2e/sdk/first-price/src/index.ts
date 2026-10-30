// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * The first-price auction (type 0, priority-expanded first price). The highest bid wins and pays its
 * own bid. Each bidder has its own region of 16 slots in the result, and a random mask hides every slot that the
 * result does not need.
 *
 * The output is `ge + m * (G + E)` per region, with `m` the sum of the bidder masks, `G` the number
 * of bids above the level and `E` the number of earlier bidders that bid exactly the level. The depth
 * is 1, and the result never fails to show the winner:
 *
 *   level p > h   every region is ZERO
 *   level p = h   the region of the winner is exactly 1 and every region before it is exactly 0.
 *                 The regions after the winner hold any value.
 *   level p < h   masked: the slots hold any value
 *
 * `h` is the highest bid. The mask only touches the slots where `G + E >= 1`, which the decoder never
 * needs, so the result is read whatever the masks hold. If one bidder is honest, the masked slots are
 * uniform, so the output shows only the winner and the price.
 *
 * @packageDocumentation
 */
import {
  assertBidderCount,
  AuctionType,
  encodeAuctionParams,
  type AuctionDesign,
  type RegionResult,
  readRegionOutput,
  rolesFor,
  slotIndex,
  type PriceList,
} from '@interfold/auction-core'
import { type Address, type Hex, zeroAddress } from 'viem'

/** The on-chain type id of this design. */
export const TYPE = AuctionType.FirstPrice

/** What this design is: its roles, what it reveals and whom the bidders trust. */
export const design: AuctionDesign = {
  type: TYPE,
  name: 'first-price',
  label: 'First-price',
  description:
    'The highest bid wins and pays its own bid, for up to 8 bidders. Only the winner and the winning bid are revealed. Each bidder has its own region of 16 slots in the result, one slot for each price step. The bidder masks hide every slot that the result does not need, and they never hide the winner. If the top bids tie, the tied bidder who bid first wins; the tie is not revealed.',
  roles: rolesFor(TYPE),
  ciphertextsPerBid: rolesFor(TYPE).length,
  providers: 'none',
  reveals: 'The winner and the price, which is the bid of the winner. Nothing else, if one bidder is honest.',
  trust: 'One honest bidder, for the randomness of the masks. No mask provider.',
}

/**
 * Encode the `customParams` of an E3 request for a first-price auction.
 *
 * @param prices The price of each step (see `priceListError` in `@interfold/auction-core`).
 * @param title The title of the auction.
 * @param gate The bidder gate contract. The zero address means that anyone may bid.
 * @param gateConfig The configuration that the gate receives. Empty when there is no gate.
 * @throws When the price list is invalid.
 */
export function encodeParams(prices: PriceList, title: string, gate: Address = zeroAddress, gateConfig: Hex = '0x'): Hex {
  return encodeAuctionParams(TYPE, prices, title, gate, gateConfig)
}

/**
 * Compute the winner and the price on the plaintext bids. The highest bid wins, and a tie goes to
 * the lowest position. The price is the highest bid.
 *
 * @param bids The bid step of each bidder, in bidder position order. 2 to 8 bids.
 * @returns The winning position and the price, as a price step.
 * @throws When there are fewer than 2 or more than 8 bids.
 */
export function expectedResult(bids: readonly number[]): { winner: number; price: number } {
  assertBidderCount(bids.length)
  const order = bids.map((_, position) => position).sort((a, b) => bids[b] - bids[a] || a - b)
  return { winner: order[0], price: bids[order[0]] }
}

/**
 * Decode the published plaintext of a first-price auction.
 *
 * The price is the highest level where some region is non-zero, and the winner is the first region
 * that is non-zero there. That region must hold exactly 1. The result is read only if the slots
 * beyond the bidder regions are zero. Any other pattern gives no price and no winner, as `null`.
 *
 * @param plaintextHex The plaintext output: `OUTPUT_COEFFS` little-endian u64 coefficients.
 * @param bidders The number of counted bids, 2 to 8. Bidder position `j` is the place of the `j`-th counted bid in leaf order.
 * @throws When `bidders` is out of range or the output is too short.
 */
export async function decodeResult(plaintextHex: string, bidders: number): Promise<RegionResult> {
  const { slots, set, unusedGroupsZero, topLevel } = await readRegionOutput(plaintextHex, bidders)
  let price: number | null = null
  let winner: number | null = null
  if (unusedGroupsZero && topLevel !== null) {
    const first = set.findIndex((row) => row[topLevel])
    if (slots[slotIndex(first, topLevel)] === 1n) {
      price = topLevel
      winner = first
    }
  }
  return { bidders, price, winner, set, unusedGroupsZero }
}
