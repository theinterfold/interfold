// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { type Hex, encodeAbiParameters, parseAbiParameters } from 'viem'

export const LEVELS = 16
export const T = 257
export const N = 128
export const MAX_BIDDERS = 112

/** `bytes32` filled with one byte. */
export const filled = (byte: number): Hex => `0x${byte.toString(16).padStart(2, '0').repeat(32)}`

// ---------------------------------------------------------------------------------------------
// Slots <-> published plaintext
// ---------------------------------------------------------------------------------------------

/**
 * The evaluation point of each SIMD slot: slot `j` of a plaintext with the coefficients `a` is
 * `sum_k a[k] * POINTS[j]^k mod 257`. It is `simd_decode` of the unit polynomial `x`; the vectors in
 * `sdk/test-vectors/slots.json` pin it against the fhe.rs decoder.
 */
export const POINTS: readonly number[] = [
  182, 119, 10, 229, 150, 76, 20, 33, 214, 163, 40, 7, 86, 238, 80, 56, 85, 152, 160, 191, 87, 69, 63, 243, 83, 219, 126, 145, 91, 47, 252,
  132, 75, 138, 247, 28, 107, 181, 237, 224, 43, 94, 217, 250, 171, 19, 177, 201, 172, 105, 97, 66, 170, 188, 194, 14, 174, 38, 131, 112,
  166, 210, 5, 125, 233, 54, 180, 156, 12, 186, 90, 148, 251, 41, 45, 147, 3, 27, 151, 179, 127, 93, 204, 183, 65, 149, 102, 55, 96, 142,
  51, 39, 209, 175, 154, 37, 24, 203, 77, 101, 245, 71, 167, 109, 6, 216, 212, 110, 254, 230, 106, 78, 130, 164, 53, 74, 192, 108, 155, 202,
  161, 115, 206, 218, 48, 82, 103, 220,
]

const modPow = (base: number, exp: number): number => {
  let result = 1
  let b = base % T
  for (let e = exp; e > 0; e >>= 1) {
    if (e & 1) result = (result * b) % T
    b = (b * b) % T
  }
  return result
}

const inverse = (value: number): number => modPow(value, T - 2)

let cachedInverse: number[][] | undefined

/** The inverse of the matrix `M[j][k] = POINTS[j]^k` modulo 257, by Gauss-Jordan elimination. */
function inverseMatrix(): number[][] {
  if (cachedInverse) return cachedInverse
  const a = POINTS.map((point, j) => [
    ...Array.from({ length: N }, (_, k) => modPow(point, k)),
    ...Array.from({ length: N }, (_, k) => (k === j ? 1 : 0)),
  ])
  for (let col = 0; col < N; col++) {
    let pivot = col
    while (pivot < N && a[pivot][col] === 0) pivot++
    if (pivot === N) throw new Error('the slot matrix is singular')
    ;[a[col], a[pivot]] = [a[pivot], a[col]]
    const scale = inverse(a[col][col])
    for (let k = 0; k < 2 * N; k++) a[col][k] = (a[col][k] * scale) % T
    for (let row = 0; row < N; row++) {
      if (row === col || a[row][col] === 0) continue
      const factor = a[row][col]
      for (let k = 0; k < 2 * N; k++) a[row][k] = (((a[row][k] - factor * a[col][k]) % T) + T) % T
    }
  }
  cachedInverse = a.map((row) => row.slice(N))
  return cachedInverse
}

/** The coefficients of the plaintext that has the SIMD slots `slots` (missing slots are 0). */
export function slotsToCoefficients(slots: readonly number[]): number[] {
  const matrix = inverseMatrix()
  return Array.from({ length: N }, (_, k) => {
    let sum = 0
    for (let j = 0; j < slots.length; j++) sum += matrix[k][j] * slots[j]
    return sum % T
  })
}

/** The slots of the plaintext with the coefficients `coefficients`. */
export function coefficientsToSlots(coefficients: readonly number[]): number[] {
  return POINTS.map((point) => {
    let acc = 0
    for (let k = N - 1; k >= 0; k--) acc = (acc * point + coefficients[k]) % T
    return acc
  })
}

/** The bytes the committee publishes for coefficients: 128 little-endian `uint64`. */
export function coefficientsToPlaintext(coefficients: readonly number[]): Hex {
  let hex = '0x'
  for (const value of coefficients) {
    hex += (value & 0xff).toString(16).padStart(2, '0') + (value >> 8).toString(16).padStart(2, '0') + '00'.repeat(6)
  }
  return hex as Hex
}

/** The published plaintext of the output with the curve `c` and the counted versions `counted`. */
export function outputPlaintext(c: readonly number[], counted: readonly number[]): Hex {
  const slots = new Array<number>(N).fill(0)
  c.forEach((value, l) => (slots[l] = value))
  counted.forEach((value, i) => (slots[16 + i] = value))
  return coefficientsToPlaintext(slotsToCoefficients(slots))
}

// ---------------------------------------------------------------------------------------------
// Sale parameters
// ---------------------------------------------------------------------------------------------

/** The `uint256[16]` of prices, as viem types it. */
type PriceTable = readonly [
  bigint,
  bigint,
  bigint,
  bigint,
  bigint,
  bigint,
  bigint,
  bigint,
  bigint,
  bigint,
  bigint,
  bigint,
  bigint,
  bigint,
  bigint,
  bigint,
]

export interface SaleParams {
  revealMode?: number
  prices: bigint[]
  saleToken: Hex
  supply: bigint
  paymentToken: Hex
  escrow: bigint
  title?: string
  gate?: Hex
  gateConfig?: Hex
}

/** `abi.encode(uint8 revealMode, uint8 levels, uint256[16] prices, address saleToken, uint256 supply, address paymentToken, uint256 escrow, string title, address gate, bytes gateConfig)`. */
export function encodeSaleParams(params: SaleParams): Hex {
  const padded = [...params.prices, ...Array.from({ length: LEVELS - params.prices.length }, () => 0n)]
  return encodeAbiParameters(
    parseAbiParameters(
      'uint8 revealMode, uint8 levels, uint256[16] prices, address saleToken, uint256 supply, address paymentToken, uint256 escrow, string title, address gate, bytes gateConfig',
    ),
    [
      params.revealMode ?? 0,
      params.prices.length,
      padded as unknown as PriceTable,
      params.saleToken,
      params.supply,
      params.paymentToken,
      params.escrow,
      params.title ?? 'Unit test sale',
      params.gate ?? '0x0000000000000000000000000000000000000000',
      params.gateConfig ?? '0x',
    ],
  )
}

/** The data of `publishInput`. */
export function encodeBidInput(input: {
  bidder: Hex
  ciphertext: Hex
  ctCommitment: Hex
  bidCommitment: Hex
  proof?: Hex
  gateProof?: Hex
  signature?: Hex
}): Hex {
  return encodeAbiParameters(
    parseAbiParameters(
      'address bidder, bytes ciphertext, bytes32 ctCommitment, bytes32 bidCommitment, bytes proof, bytes gateProof, bytes signature',
    ),
    [
      input.bidder,
      input.ciphertext,
      input.ctCommitment,
      input.bidCommitment,
      input.proof ?? '0x01',
      input.gateProof ?? '0x',
      input.signature ?? '0x',
    ],
  )
}

/** The data of `claim`: `abi.encode(uint8 cmp, bytes proof)`. */
export function encodeClaim(cmp: number, proof: Hex = '0x01'): Hex {
  return encodeAbiParameters(parseAbiParameters('uint8 cmp, bytes proof'), [cmp, proof])
}

// ---------------------------------------------------------------------------------------------
// Reference clearing (an independent TypeScript port of the spec)
// ---------------------------------------------------------------------------------------------

export const KIND_UNDERSUBSCRIBED = 0
export const KIND_CAPPED = 1
export const KIND_UNCAPPED = 2

export interface ClearingInput {
  prices: bigint[]
  /** `c[l]` for `l < prices.length`, non-increasing; the rest is 0. */
  c: bigint[]
  supply: bigint
  escrow: bigint
  unit: bigint
}

export interface ClearingResult {
  kind: number
  step: number
  pStar: bigint
  fullTokens: bigint
  marginalTokens: bigint
  sold: bigint
}

const ceilDiv = (a: bigint, b: bigint) => (a + b - 1n) / b

export function referenceClear({ prices, c, supply, escrow, unit }: ClearingInput): ClearingResult {
  const levels = prices.length
  const curve = (l: number) => (l < levels ? (c[l] ?? 0n) : 0n)
  const eu = escrow * unit
  const capped = (s: number): ClearingResult => {
    const fullTokens = eu / prices[s]
    const above = curve(s + 1)
    const marginal = curve(s) - above
    const remaining = supply - above * fullTokens
    let marginalTokens = 0n
    if (marginal > 0n) {
      marginalTokens = remaining / marginal
      if (marginalTokens > fullTokens) marginalTokens = fullTokens
    }
    return {
      kind: KIND_CAPPED,
      step: s,
      pStar: prices[s],
      fullTokens,
      marginalTokens,
      sold: above * fullTokens + marginal * marginalTokens,
    }
  }
  for (let l = levels - 1; l >= 1; l--) {
    const demand = curve(l) * eu
    if (demand > prices[l - 1] * supply) {
      if (demand >= prices[l] * supply) return capped(l)
      const pStar = ceilDiv(demand, supply)
      const fullTokens = eu / pStar
      return { kind: KIND_UNCAPPED, step: l, pStar, fullTokens, marginalTokens: 0n, sold: curve(l) * fullTokens }
    }
  }
  if (curve(0) * eu >= prices[0] * supply) return capped(0)
  const fullTokens = eu / prices[0]
  return { kind: KIND_UNDERSUBSCRIBED, step: 0, pStar: prices[0], fullTokens, marginalTokens: 0n, sold: curve(0) * fullTokens }
}

/** What a bidder with the step `b` gets: the tokens and the payment. */
export function referenceOutcome(result: ClearingResult, b: number, escrow: bigint, unit: bigint) {
  let tokens: bigint
  if (result.kind === KIND_UNDERSUBSCRIBED) tokens = result.fullTokens
  else if (result.kind === KIND_UNCAPPED) tokens = b >= result.step ? result.fullTokens : 0n
  else tokens = b > result.step ? result.fullTokens : b === result.step ? result.marginalTokens : 0n
  const paid = ceilDiv(tokens * result.pStar, unit)
  return { tokens, paid, refund: escrow - paid }
}

/** `cmp` of the claim circuit: 0 if `b < k`, 1 if `b == k`, 2 if `b > k`. */
export const compare = (b: number, k: number) => (b < k ? 0 : b === k ? 1 : 2)

/** The demand curve of the bid steps `steps`: `c[l]` is the number of steps `>= l`. */
export function demandCurve(steps: readonly number[]): number[] {
  return Array.from({ length: LEVELS }, (_, l) => steps.filter((b) => b >= l).length)
}

/** A small seeded generator, so a failing fuzz case can be replayed. */
export function rng(seed: number) {
  let state = seed >>> 0
  const next = () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0
    return state / 2 ** 32
  }
  return {
    next,
    int: (low: number, high: number) => low + Math.floor(next() * (high - low + 1)),
  }
}
