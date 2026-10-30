// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * The part of the result decoders that every design shares: the check of the bidder count and the
 * reader of the SIMD output. Each design package applies its own rule to the pattern that the reader
 * returns.
 */
import { decodePlaintextSlots } from '@interfold/sdk'
import { DEGREE, LEVELS, MAX_BIDDERS, MIN_BIDDERS, OUTPUT_COEFFS, PRESET, slotIndex } from './layout'

/** What the published result of an auction shows. Region `k` is the region of bidder position `k`. */
export interface RegionResult {
  /** Number of bidders in the round. */
  bidders: number
  /** The price the winner pays, as a price step, or `null` if the result is unreadable. */
  price: number | null
  /** The winning bidder position, or `null` if the result does not show one winner. */
  winner: number | null
  /** `set[j][level]`: whether the region of bidder position `j` is non-zero at `level`. */
  set: boolean[][]
  /** Whether the slots from `16 n` on are zero, as the program makes them. */
  unusedGroupsZero: boolean
}

/** The non-zero pattern of a published output, before a design applies its rule. */
export interface RegionOutput {
  /** The decoded SIMD slot values: `DEGREE` values in `[0, PLAINTEXT_MODULUS)`. */
  slots: readonly bigint[]
  /** `set[j][level]`: whether the region of bidder position `j` is non-zero at `level`. */
  set: boolean[][]
  /** Whether the slots from `16 n` on are zero. */
  unusedGroupsZero: boolean
  /** The highest level at which some region is non-zero, or `null` when every region is zero. */
  topLevel: number | null
}

/**
 * Check that an auction has a valid number of bidders.
 *
 * @param bidders The number of counted bids.
 * @throws When `bidders` is outside `MIN_BIDDERS` to `MAX_BIDDERS`.
 */
export function assertBidderCount(bidders: number): void {
  if (!Number.isInteger(bidders) || bidders < MIN_BIDDERS || bidders > MAX_BIDDERS) {
    throw new Error(`An auction has ${MIN_BIDDERS} to ${MAX_BIDDERS} bidders, got ${bidders}`)
  }
}

/**
 * Read the published plaintext of an auction as `bidders` regions of `LEVELS` slots.
 *
 * @param plaintextHex The plaintext output: `OUTPUT_COEFFS` little-endian u64 coefficients, with or without `0x`.
 * @param bidders The number of counted bids. Bidder position `j` is the place of the `j`-th counted bid in leaf order.
 * @throws When `bidders` is out of range, or the output is too short to hold `OUTPUT_COEFFS` coefficients.
 */
export async function readRegionOutput(plaintextHex: string, bidders: number): Promise<RegionOutput> {
  assertBidderCount(bidders)
  const hex = plaintextHex.startsWith('0x') ? plaintextHex.slice(2) : plaintextHex
  if (hex.length < OUTPUT_COEFFS * 16) {
    throw new Error(`Plaintext output has ${hex.length / 2} bytes, expected ${OUTPUT_COEFFS * 8}`)
  }
  const slots = await decodePlaintextSlots(`0x${hex}`, PRESET)
  if (slots.length < DEGREE) throw new Error(`Decoded ${slots.length} slots, expected ${DEGREE}`)
  const set = Array.from({ length: bidders }, (_, region) =>
    Array.from({ length: LEVELS }, (_, level) => slots[slotIndex(region, level)] !== 0n),
  )
  let unusedGroupsZero = true
  for (let slot = bidders * LEVELS; slot < DEGREE; slot++) if (slots[slot] !== 0n) unusedGroupsZero = false
  const lasts = set.map((row) => row.lastIndexOf(true)).filter((level) => level >= 0)
  return { slots, set, unusedGroupsZero, topLevel: lasts.length > 0 ? Math.max(...lasts) : null }
}
