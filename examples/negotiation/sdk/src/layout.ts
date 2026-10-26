// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * The encoding that the two parties, the offer circuit (`negotiation_offer`), the FHE program
 * (`program/src/lib.rs`) and the contract (`libraries/NegotiationOutput.sol`) share. `DESIGN.md` explains why
 * it has this shape. Every plaintext is SIMD-encoded over the 128 slots of the ring.
 *
 * A party has a private price step (`step`, the seller's minimum or the buyer's maximum) and a private
 * random `share` (4 bits). It sends 3 ciphertexts:
 *
 * ```text
 *   ciphertext 0   lane tensor, lanes 0..7    slot LANE * 16 + i = tensor(lane, i)
 *   ciphertext 1   lane tensor, lanes 8..15   slot LANE * 16 + i = tensor(lane + 8, i)
 *   ciphertext 2   mask                       random values, with the sum over the 8 groups of a level = 0 mod t
 * ```
 *
 * The program computes `out = X0 * Y0 + X1 * Y1 + M_seller + M_buyer` slot by slot (one ciphertext
 * multiplication of depth 1, two of them). After the decryption, `sum_{g < 8} out[g * 16 + i]` is 1 for the
 * price level `i` of the agreed price and 0 for every other level. The 8 group values of a level are
 * uniform subject to their sum, so they carry nothing else.
 */
import { decodePlaintextSlots } from '@interfold/sdk'

/** Polynomial degree, and so the slot count, of the insecure SIMD preset (param set 5). */
export const DEGREE = 128
/** Plaintext modulus of the same preset: prime, 1 mod 2 * DEGREE, so it supports SIMD. */
export const PLAINTEXT_MODULUS = 257n
/** The preset name the SDK and the program use. */
export const PRESET = 'INSECURE_THRESHOLD_SIMD' as const
/** The most price levels of a negotiation: the slots of one group. A price step is in `[0, LEVELS)`. */
export const LEVELS = 16
/** The fewest price levels of a negotiation. */
export const MIN_LEVELS = 2
/** The groups of 16 slots in a plaintext: the 8 lanes that one ciphertext holds. */
export const GROUPS = DEGREE / LEVELS
/** The bits of the random share of a party. The shared pointer `u = a xor c` has `SHARE_BITS` bits. */
export const SHARE_BITS = 4
/** The lanes of the lane tensor: one for each value of `SHARE_BITS` bits. */
export const LANES = 1 << SHARE_BITS
/** The ciphertexts of one offer: lanes 0..7, lanes 8..15 and the mask. */
export const OFFER_CIPHERTEXTS = 3
/** Coefficients the committee publishes after decryption for this preset. */
export const OUTPUT_COEFFS = DEGREE

/** The two parties. The values are the `uint8` the contract uses. */
export enum Role {
  Seller = 0,
  Buyer = 1,
}

const MODULUS = Number(PLAINTEXT_MODULUS)

function bit(value: number, k: number): number {
  return (value >> k) & 1
}

/**
 * The largest level below `i` that beats `i` when the pointer bit `k` is 0 and `i` has the bit `k`: `i`
 * with the bit `k` cleared and every lower bit set. The seller's own side of the trie.
 */
export function leftReach(i: number, k: number): number {
  return ((i >> (k + 1)) << (k + 1)) | ((1 << k) - 1)
}

/**
 * The smallest level above `i` that beats `i` when the pointer bit `k` is 1 and `i` has not the bit
 * `k`: `i` with the bit `k` set and every lower bit cleared. The buyer's own side of the trie.
 */
export function rightReach(i: number, k: number): number {
  return ((i >> (k + 1)) << (k + 1)) | (1 << k)
}

/**
 * The tensor entry of `role` for the lane `theta` (0..15) at the level `i`.
 *
 * With the pointer `u`, the program picks the level of the least `l xor u` in `[s, b]`. The level `i`
 * wins if no level of `[s, i)` beats it (this depends on `u` at the 1-bits of `i`, and on `s`) and no level
 * of `(i, b]` beats it (the 0-bits of `i`, and `b`). The seller holds the first half, the buyer the second;
 * `u = a xor c` hides each half behind the share of the other party. The sum over `theta` of
 * `seller(theta) * buyer(theta)` is 1 if `i` wins and 0 otherwise.
 */
export function tensorEntry(role: Role, theta: number, i: number, step: number, share: number): 0 | 1 {
  if (role === Role.Seller ? step > i : step < i) return 0
  for (let k = 0; k < SHARE_BITS; k++) {
    const own = bit(i, k) === (role === Role.Seller ? 1 : 0)
    if (own) {
      // The pointer bit is the xor of this party's bit and the other's: the lane holds the other's bit.
      const reach = role === Role.Seller ? step <= leftReach(i, k) : step >= rightReach(i, k)
      const pointerBit = bit(share, k) ^ bit(theta, k)
      // The own-side factor is 0 only if the pointer bit makes a level in reach beat `i`.
      const killed = role === Role.Seller ? pointerBit === 0 && reach : pointerBit === 1 && reach
      if (killed) return 0
    } else if (bit(share, k) !== bit(theta, k)) {
      // The lane holds this party's own bit on the other party's side of the trie.
      return 0
    }
  }
  return 1
}

/** The values of the two lane ciphertexts of an offer, as the 128 SIMD slots of each. */
export function laneSlots(role: Role, step: number, share: number): [BigUint64Array, BigUint64Array] {
  assertStep(step, LEVELS)
  assertShare(share)
  const half = [new BigUint64Array(DEGREE), new BigUint64Array(DEGREE)] as [BigUint64Array, BigUint64Array]
  for (let theta = 0; theta < LANES; theta++) {
    for (let i = 0; i < LEVELS; i++) {
      const entry = tensorEntry(role, theta, i, step, share)
      half[theta >> 3][(theta & 7) * LEVELS + i] = BigInt(entry)
    }
  }
  return half
}

/**
 * A mask: random slots below `t` whose sum over the 8 groups of each level is 0 mod `t`. `random` returns an
 * integer in `[0, t)`. The default is `crypto.getRandomValues` with rejection, so the mask is uniform.
 */
export function maskSlots(random: () => number = secureRandom): BigUint64Array {
  const slots = new BigUint64Array(DEGREE)
  for (let i = 0; i < LEVELS; i++) {
    let sum = 0
    for (let g = 0; g < GROUPS - 1; g++) {
      const value = random()
      slots[g * LEVELS + i] = BigInt(value)
      sum += value
    }
    slots[(GROUPS - 1) * LEVELS + i] = BigInt((MODULUS - (sum % MODULUS)) % MODULUS)
  }
  return slots
}

function secureRandom(): number {
  // 256 * 1 values of a byte cover [0, 257) only with rejection: draw 16 bits and reject the tail.
  const limit = 65536 - (65536 % MODULUS)
  const buffer = new Uint16Array(1)
  for (;;) {
    crypto.getRandomValues(buffer)
    if (buffer[0] < limit) return buffer[0] % MODULUS
  }
}

/** A random share: 4 uniform bits. */
export function randomShare(): number {
  const buffer = new Uint8Array(1)
  crypto.getRandomValues(buffer)
  return buffer[0] & (LANES - 1)
}

/** The three plaintexts (slot values) of an offer, in the order of the ciphertexts. */
export function offerSlots(role: Role, step: number, share: number, mask: BigUint64Array = maskSlots()): BigUint64Array[] {
  const [lanes0, lanes1] = laneSlots(role, step, share)
  return [lanes0, lanes1, mask]
}

/**
 * The output the program computes for the seller's and the buyer's plaintexts:
 * `X0 * Y0 + X1 * Y1 + M_s + M_b` slot by slot, mod `t`.
 */
export function combineOffers(seller: readonly BigUint64Array[], buyer: readonly BigUint64Array[]): BigUint64Array {
  const t = PLAINTEXT_MODULUS
  const out = new BigUint64Array(DEGREE)
  for (let slot = 0; slot < DEGREE; slot++) {
    out[slot] = (seller[0][slot] * buyer[0][slot] + seller[1][slot] * buyer[1][slot] + seller[2][slot] + buyer[2][slot]) % t
  }
  return out
}

/** The outcome of a negotiation. `step` is the price level of the agreed price, `null` if there is no match. */
export interface Outcome {
  matched: boolean
  step: number | null
}

/** `sum_{g < 8} slots[g * 16 + i] mod t` for each level `i`: the one-hot of the agreed level. */
export function levelSums(slots: ArrayLike<bigint | number>): bigint[] {
  if (slots.length !== DEGREE) throw new Error(`the output has ${DEGREE} slots, got ${slots.length}`)
  const sums: bigint[] = []
  for (let i = 0; i < LEVELS; i++) {
    let sum = 0n
    for (let g = 0; g < GROUPS; g++) sum += BigInt(slots[g * LEVELS + i])
    sums.push(sum % PLAINTEXT_MODULUS)
  }
  return sums
}

/** Reads the output slots. It throws if the level sums are not the one-hot vector of one level or the zero vector. */
export function readOutputSlots(slots: ArrayLike<bigint | number>): Outcome {
  const sums = levelSums(slots)
  let step: number | null = null
  sums.forEach((sum, level) => {
    if (sum === 0n) return
    if (sum !== 1n || step !== null) throw new Error('the output is not a valid outcome')
    step = level
  })
  return { matched: step !== null, step }
}

/** Decodes the plaintext output the committee published (hex of 128 u64-LE polynomial coefficients). */
export async function decodeOutput(plaintextOutput: string): Promise<Outcome> {
  const hex = plaintextOutput.startsWith('0x') ? plaintextOutput.slice(2) : plaintextOutput
  return readOutputSlots(await decodePlaintextSlots(`0x${hex}`, PRESET))
}

/** The outcome that two private steps and two shares give, with the same rule as the program: the level of the least `i xor u` in `[s, b]`. */
export function expectedOutcome(sellerStep: number, buyerStep: number, sellerShare: number, buyerShare: number): Outcome {
  if (sellerStep > buyerStep) return { matched: false, step: null }
  const pointer = sellerShare ^ buyerShare
  let best = sellerStep
  for (let i = sellerStep; i <= buyerStep; i++) if ((i ^ pointer) < (best ^ pointer)) best = i
  return { matched: true, step: best }
}

export function assertStep(step: number, levels: number): void {
  if (!Number.isInteger(step) || step < 0 || step >= levels) throw new Error(`the price step must be in [0, ${levels}), got ${step}`)
}

export function assertShare(share: number): void {
  if (!Number.isInteger(share) || share < 0 || share >= LANES) throw new Error(`the share must be in [0, ${LANES}), got ${share}`)
}

/** The price of the level `step`: `minPrice + step * stepSize`. */
export function priceAt(minPrice: bigint, stepSize: bigint, step: number): bigint {
  return minPrice + BigInt(step) * stepSize
}

/**
 * The price grid of a public `[min, max, stepSize]` range: `levels = (max - min) / stepSize + 1` levels, or `null`
 * (with the reason) if the range is not a whole number of steps between 2 and `LEVELS` levels.
 */
export function gridFor(min: bigint, max: bigint, stepSize: bigint): { levels: number } | { error: string } {
  if (stepSize <= 0n) return { error: 'the step must be positive' }
  if (max <= min) return { error: 'the maximum must be above the minimum' }
  if ((max - min) % stepSize !== 0n) return { error: 'the range must be a whole number of steps' }
  const levels = (max - min) / stepSize + 1n
  if (levels < BigInt(MIN_LEVELS) || levels > BigInt(LEVELS))
    return { error: `the range must have ${MIN_LEVELS} to ${LEVELS} levels, got ${levels}` }
  return { levels: Number(levels) }
}

/** The price step of a whole-number price inside the grid, or an error. */
export function stepFor(price: bigint, min: bigint, stepSize: bigint, levels: number): number | { error: string } {
  if (price < min) return { error: 'the price is below the minimum' }
  if ((price - min) % stepSize !== 0n) return { error: 'the price is not on the grid' }
  const step = (price - min) / stepSize
  if (step >= BigInt(levels)) return { error: 'the price is above the maximum' }
  return Number(step)
}
