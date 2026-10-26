// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { Hex } from 'viem'

export const T = 257
export const N = 128

/** `bytes32` filled with one byte. */
export const filled = (byte: number): Hex => `0x${byte.toString(16).padStart(2, '0').repeat(32)}`

/** A `uint256` as `bytes32`. */
export const bytes32 = (value: bigint | number): Hex => `0x${BigInt(value).toString(16).padStart(64, '0')}`

/**
 * The evaluation point of each SIMD slot: slot `j` of a plaintext with the coefficients `a` is
 * `sum_k a[k] * POINTS[j]^k mod 257`. It is `simd_decode` of the unit polynomial `x`.
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
    const scale = modPow(a[col][col], T - 2)
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
export function slotsToCoefficients(slots: ArrayLike<number | bigint>): number[] {
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

/** The published plaintext of the output with the SIMD slots `slots`. */
export const plaintextOfSlots = (slots: ArrayLike<number | bigint>): Hex => coefficientsToPlaintext(slotsToCoefficients(slots))

/**
 * The output slots with the level sums `sums`: the sum of the 8 groups of level `i` is `sums[i]` mod 257. The
 * group values come from `random`, so the slots look like a real output (uniform subject to the sum).
 */
export function slotsWithSums(sums: readonly number[], random: () => number): number[] {
  const slots = new Array<number>(N).fill(0)
  for (let i = 0; i < 16; i++) {
    let rest = sums[i] ?? 0
    for (let g = 0; g < 7; g++) {
      const value = random()
      slots[g * 16 + i] = value
      rest -= value
    }
    slots[7 * 16 + i] = ((rest % T) + T) % T
  }
  return slots
}

/** A small seeded generator of integers in `[0, T)`, so a failing case can be replayed. */
export function rng(seed: number): () => number {
  let state = seed >>> 0
  return () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0
    return (state >>> 8) % T
  }
}
