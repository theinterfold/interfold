// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * The second-price auction with mask providers (type 1, E). The highest bid wins and pays the
 * second-highest bid. Each bid has 2 ciphertexts: `[ge, gt]`, with no mask of its own.
 *
 * The creator names 1 to {@link MAX_PROVIDERS} mask providers. Each one sends one mask ciphertext
 * whose 128 slots are all non-zero, and the proof of the mask checks it. The output is `tests * r`,
 * with `r` the product of the masks: every test is below the plaintext modulus, so a non-zero slot is
 * NEVER read as zero, and the result never fails to show the winner. If one provider is honest, each
 * non-zero slot is uniform. Privacy needs 1 honest provider out of 1 to 4. Correctness needs
 * nobody. Liveness needs every provider: without all masks the auction cannot run (see
 * {@link checkMasks}).
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
export const TYPE = AuctionType.ProviderSecondPrice

/** What this design is: its roles, what it reveals and whom the bidders trust. */
export const design: AuctionDesign = {
  type: TYPE,
  name: 'provider-second-price',
  label: 'Second-price, mask providers',
  description:
    'The highest bid wins and pays the second-highest bid, for up to 8 bidders. Only the winner and that price are revealed. The auction names 1 to 4 mask providers. Each one sends a random mask before bidding opens. If one provider is honest, the result shows nothing else, and it can never fail to show the winner. If the top bids tie, the tied bidder who bid first wins; the tie is not revealed.',
  roles: rolesFor(TYPE),
  ciphertextsPerBid: rolesFor(TYPE).length,
  providers: 'required',
  reveals: 'The winner and the price, which is the second-highest bid. Nothing else, if one provider is honest.',
  trust:
    'Privacy needs 1 honest mask provider out of the 1 to 4 that the auction names. Correctness needs nobody. Liveness needs every provider to send its mask.',
}

/**
 * Encode the `customParams` of an E3 request for a second-price auction with mask providers.
 *
 * @param prices The price of each step (see `priceListError` in `@interfold/auction-core`).
 * @param title The title of the auction.
 * @param providers The mask providers: 1 to {@link MAX_PROVIDERS} different non-zero addresses. Every one must send a mask before the auction can run.
 * @param gate The bidder gate contract. The zero address means that anyone may bid.
 * @param gateConfig The configuration that the gate receives. Empty when there is no gate.
 * @throws When the price list or the provider list is invalid.
 */
export function encodeParams(
  prices: PriceList,
  title: string,
  providers: readonly Address[],
  gate: Address = zeroAddress,
  gateConfig: Hex = '0x',
): Hex {
  return encodeAuctionParams(TYPE, prices, title, gate, gateConfig, providers)
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
 * Decode the published plaintext of a second-price auction with mask providers.
 *
 * The pattern is strict. The result is read only if the slots beyond the bidder regions are zero, no
 * slot above the price is non-zero, exactly one region is zero at the price, and every slot below
 * the price is non-zero. Any other pattern gives no price and no winner, as `null`. A valid output
 * always matches the pattern, because every provider mask is proven non-zero in every slot and every
 * test is below the plaintext modulus.
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

export { MASK_VERSION, MAX_PROVIDERS, providersError } from '@interfold/auction-core'
export { checkMasks, encodeMaskInput, type MaskStatus, type SubmittedMask } from './masks'
