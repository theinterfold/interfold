// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * The second-price auction with no mask providers (type 2, E-QNR). The highest bid wins and pays the
 * second-highest bid. Each bid has 4 ciphertexts: `[ge, gt, share, share]`.
 *
 * The program adds the shares of the counted bids, `S1` and `S2`, and multiplies the tests by
 * `(S1^2 - 3) * (S2^2 - 3)`. 3 is not a square modulo the plaintext modulus (257) and not modulo
 * 65537, so no factor is ever zero and a non-zero slot is NEVER read as zero, whatever the bidders
 * send. The factor is not exactly uniform, so the non-zero slots show a small statistical hint about
 * the counts of the tests: at most 0.36 bits per auction on the demo preset, and 0.19 bits on a
 * secure 16384-slot preset.
 *
 * The result has the second-price pattern:
 *
 *   level p < s   every region is non-zero
 *   level p = s   the region of the winner is ZERO, every other region is non-zero
 *   level p > s   every region is zero
 *
 * `s` is the second-highest bid. The decoder is strict and reads no result from any other pattern.
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
  type PriceList,
} from '@interfold/auction-core'
import { type Address, type Hex, zeroAddress } from 'viem'

/** The on-chain type id of this design. */
export const TYPE = AuctionType.QnrSecondPrice

/** What this design is: its roles, what it reveals and whom the bidders trust. */
export const design: AuctionDesign = {
  type: TYPE,
  name: 'qnr-second-price',
  label: 'Second-price, no providers',
  description:
    'The highest bid wins and pays the second-highest bid, for up to 8 bidders. Only the winner and that price are revealed. There are no mask providers and no trusted party: each bid carries two random shares, and the program mixes the shares of all bids into a random factor. The result can never fail to show the winner. The trade-off is a small statistical hint about the losing bids, larger on the demo parameters than on secure ones. If the top bids tie, the tied bidder who bid first wins; the tie is not revealed.',
  roles: rolesFor(TYPE),
  ciphertextsPerBid: rolesFor(TYPE).length,
  providers: 'none',
  reveals:
    'The winner and the price, which is the second-highest bid. Also a faint statistical hint: at most 0.36 bits per auction on the demo preset, and 0.19 bits on a secure 16384-slot preset.',
  trust: 'Only yourself. No mask provider and no trusted party.',
}

/**
 * Encode the `customParams` of an E3 request for a no-provider second-price auction.
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
 * the lowest position. The price is the second-highest bid.
 *
 * @param bids The bid step of each bidder, in bidder position order. 2 to 8 bids.
 * @returns The winning position and the price, as a price step.
 * @throws When there are fewer than 2 or more than 8 bids.
 */
export function expectedResult(bids: readonly number[]): { winner: number; price: number } {
  assertBidderCount(bids.length)
  const order = bids.map((_, position) => position).sort((a, b) => bids[b] - bids[a] || a - b)
  return { winner: order[0], price: bids[order[1]] }
}

/**
 * Decode the published plaintext of a no-provider second-price auction.
 *
 * The pattern is strict. The result is read only if the slots beyond the bidder regions are zero, no
 * slot above the price is non-zero, exactly one region is zero at the price, and every slot below
 * the price is non-zero. Any other pattern gives no price and no winner, as `null`. A valid output
 * always matches the pattern, because the factor is never zero and every test is below the
 * plaintext modulus.
 *
 * @param plaintextHex The plaintext output: `OUTPUT_COEFFS` little-endian u64 coefficients.
 * @param bidders The number of counted bids, 2 to 8. Bidder position `j` is the place of the `j`-th counted bid in leaf order.
 * @throws When `bidders` is out of range or the output is too short.
 */
export async function decodeResult(plaintextHex: string, bidders: number): Promise<RegionResult> {
  const { set, unusedGroupsZero, topLevel } = await readRegionOutput(plaintextHex, bidders)
  let price: number | null = null
  let winner: number | null = null
  if (unusedGroupsZero && topLevel !== null) {
    const winners = set.flatMap((row, region) => (row[topLevel] ? [] : [region]))
    const belowSet = set.every((row) => row.slice(0, topLevel).every(Boolean))
    if (winners.length === 1 && belowSet) {
      price = topLevel
      winner = winners[0]
    }
  }
  return { bidders, price, winner, set, unusedGroupsZero }
}
