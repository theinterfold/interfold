// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { type Hex, encodeAbiParameters, parseAbiParameters, zeroAddress } from 'viem'
import { DEGREE, LEVELS, MAX_BIDDERS, type RoundParams } from '../sdk/src/layout'

export { LEVELS, MAX_BIDDERS }
export const T = 257
export const N = DEGREE

/** `bytes32` filled with one byte. */
export const filled = (byte: number): Hex => `0x${byte.toString(16).padStart(2, '0').repeat(32)}`

export const bytes32 = (value: bigint | number | string) => `0x${BigInt(value).toString(16).padStart(64, '0')}` as Hex

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
export function slotsToCoefficients(slots: readonly (number | bigint)[]): number[] {
  const matrix = inverseMatrix()
  return Array.from({ length: N }, (_, k) => {
    let sum = 0
    for (let j = 0; j < slots.length; j++) sum += matrix[k][j] * Number(slots[j])
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

/** The published plaintext of the output slots `slots` (up to 128 values). */
export const plaintextOf = (slots: readonly (number | bigint)[]): Hex => coefficientsToPlaintext(slotsToCoefficients(slots))

// ---------------------------------------------------------------------------------------------
// Request parameters
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

/** The fields of the request, with no check: the tests use it to build bad requests too. */
export interface RawParams {
  levels?: number
  /** Padded with zeros to 16 values. */
  prices: bigint[]
  saleToken: Hex
  lot: bigint
  lots: number
  reserveStep: number
  minLots: number
  paymentToken: Hex
  title?: string
  gate?: Hex
  gateConfig?: Hex
}

/** `abi.encode(uint8 levels, uint256[16] prices, address saleToken, uint256 lot, uint8 lots, uint8 reserveStep, uint8 minLots, address paymentToken, string title, address gate, bytes gateConfig)`. */
export function encodeRawParams(params: RawParams): Hex {
  const padded = [...params.prices, ...Array.from({ length: Math.max(0, LEVELS - params.prices.length) }, () => 0n)]
  return encodeAbiParameters(
    parseAbiParameters(
      'uint8 levels, uint256[16] prices, address saleToken, uint256 lot, uint8 lots, uint8 reserveStep, uint8 minLots, address paymentToken, string title, address gate, bytes gateConfig',
    ),
    [
      params.levels ?? params.prices.length,
      padded as unknown as PriceTable,
      params.saleToken,
      params.lot,
      params.lots,
      params.reserveStep,
      params.minLots,
      params.paymentToken,
      params.title ?? 'Unit test round',
      params.gate ?? zeroAddress,
      params.gateConfig ?? '0x',
    ],
  )
}

export const roundParamsOf = (prices: readonly bigint[], reserveStep: number, lots: number, minLots: number): RoundParams => ({
  levels: prices.length,
  reserveStep,
  lots,
  minLots,
})

/** A small seeded generator, so a failing random case can be replayed. */
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
