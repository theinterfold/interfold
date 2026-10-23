// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * What every design shares: the auction setup, the public result, the tie rule, and the
 * `Design` interface. A tie goes to the bidder with the higher tie priority (`Setup.tiePriority`).
 * The priority is the index, except for the designs that draw a random order after the bids close
 * (`Design.randomTieOrder`).
 */

import type { Ciphertext, Evaluator } from '../evaluator'
import { Ring, type Profile, type Slots } from '../field'
import type { Rng } from '../rng'

/** One auction: parameters, number of bidders, and bid range `0..levels`. */
export interface Setup {
  profile: Profile
  ring: Ring
  bidders: number
  levels: number
  /**
   * The tie priority of each bidder: a permutation of `0..bidders`. On a tie, the higher priority
   * wins. It is the identity, except for designs with `randomTieOrder`.
   */
  tiePriority: number[]
}

/** A setup where the tie priority is the bidder index, unless `tiePriority` is given. */
export function newSetup(profile: Profile, bidders: number, levels: number, tiePriority?: number[]): Setup {
  return {
    profile,
    ring: Ring.fromProfile(profile),
    bidders,
    levels,
    tiePriority: tiePriority ?? Array.from({ length: bidders }, (_, i) => i),
  }
}

/** The price that a design makes public. */
export type PriceRule =
  /** No price. The winner opens a bid commitment outside the program. */
  | 'none'
  /** The winning bid. */
  | 'first'
  /** The second-highest bid (Vickrey). */
  | 'second'

/**
 * What everybody can read from the decrypted output. `null` means "not named". The ratio-lane
 * designs also publish the tie set and the random value that picked the winner from it.
 */
export interface PublicResult {
  /** `null` when the output does not name exactly one winner. */
  winner: number | null
  price: number | null
  /** Ratio-lane designs only: the bidders whose bid is the price, in ascending order. `[]` if unreadable. */
  tieSet?: number[]
  /** Ratio-lane designs only: the value of the random lane. */
  random?: number
}

/** What a lane holds: 0, a uniform value, or the part of the result that the reader takes from it. */
export type LaneKind = 'zero' | 'random' | 'result'

/** One lane of a ratio-lane output: the value at each price level. */
export interface LaneRow {
  name: string
  values: number[]
  kinds: LaneKind[]
}

/** How a ratio-lane output reads, for display. See `designs/ratio-common.ts`. */
export interface LaneReadout {
  /** The price level, or `null` when no lane is non-zero. */
  price: number | null
  /** The bidders whose bid is the price, ascending. `[]` when the output does not decode. */
  tieSet: number[]
  /** For each weight group, the value that the reader takes at the price level (the group's tie weights). */
  groupValues: number[]
  /** The bidder count of each weight group. */
  groupSizes: number[]
  /** The value of the random lane. */
  random: number
  /** `tieSet[random mod |tieSet|]`, or `null` when the output does not decode. */
  winner: number | null
  /** Copies of the lanes: 1 for the first price. */
  copies: number
  /** The copy that `rows` shows: the first that fixed the price. */
  copy: number
  /** Whether every copy that fixed the price gives the same group values. */
  copiesAgree: boolean
  /** The lanes of copy `copy`. */
  rows: LaneRow[]
}

/** Bidder indices from the winner down. A tie goes to the higher `tiePriority`. */
export function ranking(bids: number[], tiePriority: number[]): number[] {
  const order = bids.map((_, i) => i)
  order.sort((a, b) => bids[b] - bids[a] || tiePriority[b] - tiePriority[a])
  return order
}

/** The result computed on plaintext bids, with ties broken by `tiePriority`. */
export function expectedResult(bids: number[], rule: PriceRule, tiePriority: number[]): PublicResult {
  const order = ranking(bids, tiePriority)
  const price = rule === 'none' ? null : rule === 'first' ? bids[order[0]] : bids[order[1]]
  return { winner: order[0], price }
}

/** The 1-based rank of each bidder (1 = winner). A tie goes to the higher index. */
export function ranks(bids: number[]): number[] {
  const result = new Array<number>(bids.length).fill(0)
  const order = ranking(
    bids,
    bids.map((_, i) => i),
  )
  order.forEach((index, position) => {
    result[index] = position + 1
  })
  return result
}

/** What one bidder sends: the plaintext of each ciphertext, and what it keeps for itself. */
export interface Encoded<Secret = undefined> {
  /**
   * One slot vector for each ciphertext. A polynomial plaintext (`rank`, masks with a zero
   * coefficient) is given by its slots: `Ring.toSlots` of its coefficients.
   */
  plaintexts: Slots[]
  secret: Secret
}

/**
 * Where the regions of an output vector sit, so that `--trace` can print a vector by region and
 * level.
 */
export interface Region {
  name: string
  start: number
  length: number
  /** Values in one printed row. The row index is a level, a bid, or a window. */
  width?: number
  /** What a row counts, for example `bid`. */
  rowName?: string
}

export interface Layout {
  /** Whether the design reads slots or coefficients. The trace prints that form. */
  domain: 'slots' | 'coefficients'
  regions: Region[]
  /** One line that tells how to read the regions. */
  note?: string
  /** What the columns of a region without `width` count. Default `level p`. */
  columnName?: string
  /** Single values to print after the regions, for example the published scores. */
  points?: { name: string; index: number }[]
}

/** A program for a sealed-bid auction, with its client-side encoding and its decoding. */
export interface Design<Secret = undefined> {
  readonly name: string
  /** What the decrypted output reveals, in one line. */
  readonly disclosure: string
  readonly priceRule: PriceRule
  /** How a contract reads the result from the published plaintext, in one line. */
  readonly readout: string
  /** The names of the ciphertexts that each bidder sends, in order. Used by `--trace`. */
  readonly inputNames: readonly string[]
  /**
   * Whether the program breaks ties with `Setup.tiePriority`, drawn at random after the bids
   * close. Only a design whose submissions do not depend on the bidder index can do this. The
   * other designs break ties by index.
   */
  readonly randomTieOrder: boolean
  /** The number of ct×ct products on the longest path of the program. */
  depth(bidders: number): number
  /** Throws a `SetupError` when the slots or the plaintext modulus cannot hold this auction. */
  check(setup: Setup): void
  /** The plaintexts that bidder `index` encrypts. */
  encodeBid(setup: Setup, index: number, bid: number, rng: Rng): Encoded<Secret>
  /** The program: all submissions in, one ciphertext out. */
  evaluate(setup: Setup, inputs: Ciphertext[][], evaluator: Evaluator): Ciphertext
  /** Reads the public result from the decrypted output slots. */
  decode(setup: Setup, outputSlots: Slots): PublicResult
  /** Where the regions of a vector sit, for `--trace`. */
  layout(setup: Setup): Layout
  /**
   * Whether the program breaks a tie with a random lane: the sum of the masks in one slot. The
   * winner is the tie set member at the position `random mod |tie set|`. A design with a random
   * lane also has `expected` and `readLanes`.
   */
  readonly randomLane?: boolean
  /**
   * The result that the program must output, from the plaintext bids and submissions. A design
   * with a random lane needs the submissions: the random value is the sum of the masks.
   */
  expected?(setup: Setup, bids: number[], inputs: Slots[][]): PublicResult
  /** The lanes of the output and the values that the reader takes from them. */
  readLanes?(setup: Setup, outputSlots: Slots): LaneReadout
  /** Whether each bidder can read its own rank from the output with its secret. */
  readonly revealsOwnRank: boolean
  /** The rank that bidder `index` reads with its secret. `null` when the value does not decode. */
  ownRank?(setup: Setup, outputSlots: Slots, index: number, secret: Secret): number | null
  /** The rank that each bidder must read, for designs that reveal it. */
  expectedRanks?(bids: number[]): number[]
}

export type SetupErrorKind = 'too-few-bidders' | 'bid-out-of-range' | 'not-enough-slots' | 'plaintext-modulus-too-small' | 'depth-too-large'

/** An auction that the profile cannot hold. */
export class SetupError extends Error {
  constructor(
    readonly kind: SetupErrorKind,
    message: string,
  ) {
    super(message)
    this.name = 'SetupError'
  }
}

export const setupErrors = {
  tooFewBidders: (bidders: number) => new SetupError('too-few-bidders', `an auction needs 2 or more bidders, got ${bidders}`),
  bidOutOfRange: (index: number, bid: number, levels: number) =>
    new SetupError('bid-out-of-range', `bid ${bid} of bidder ${index} is not in 0..${levels}`),
  notEnoughSlots: (needed: number, available: number) =>
    new SetupError('not-enough-slots', `the design needs ${needed} slots, the ring has ${available}: use fewer bidders or levels`),
  plaintextModulusTooSmall: (needed: number, modulus: number) =>
    new SetupError(
      'plaintext-modulus-too-small',
      `the design encodes values up to ${needed}, the plaintext modulus is ${modulus}: use fewer bidders or levels`,
    ),
  depthTooLarge: (depth: number, requiredBits: number, limitBits: number) =>
    new SetupError(
      'depth-too-large',
      `depth ${depth} needs log2(q) = ${requiredBits.toFixed(1)}, the security limit is ${limitBits.toFixed(1)}: use fewer bidders`,
    ),
}

/** Shared capacity check: `slots` SIMD slots or coefficients, and encoded values up to `values`. */
export function checkCapacity(setup: Setup, slots: number, values: number): void {
  const available = setup.ring.degree
  if (slots > available) throw setupErrors.notEnoughSlots(slots, available)
  if (values > setup.ring.t) throw setupErrors.plaintextModulusTooSmall(values, setup.ring.t)
}

/** `⌈log2 n⌉` for `n ≥ 1`. */
export function treeDepth(n: number): number {
  return n <= 1 ? 0 : Math.ceil(Math.log2(n))
}
