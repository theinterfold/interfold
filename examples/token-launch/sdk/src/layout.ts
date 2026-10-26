// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * The encoding that the bidders, the bid circuit (`token_launch_bid`), the FHE program
 * (`program/src/lib.rs`, the single source), the program contract (`SlotCodec`, `SaleOutput`) and the
 * result decoder share. `test-vectors/layout.json` is generated from the Rust source and pins this file.
 *
 * All ciphertexts are SIMD-encoded over the 128 slots of the ring. One bid is one plaintext, encrypted
 * once under each of the two E3 keys. For the budget `B` (1..=4095, base 4 digits `d_0..d_5`, little
 * endian), the max price step `b` and the bid index `i`:
 *
 *   slot l * LANES + j  (l < LEVELS_MAX, j < LANES)    d_j if l <= b, else 0
 *   slot FLAG_BASE + floor(i / 8)                      2^(i % 8)
 *   every other slot                                   0
 *
 * The sum of the counted bids has, at the level `l`, the cells `sum_i d_j(B_i) [b_i >= l]` (at most 255,
 * so no slot wraps modulo 257) and the counted bitmap in the flag cells. `F_l = sum_j 4^j cells[l][j]`
 * is the budget sum of the bids with a step of at least `l`.
 *
 * The output of an E3 is that sum times a 0/1 keep mask: it keeps the cells of the probed levels (bit
 * `l` of `probeMask`) and all the flag cells. The committee publishes the plaintext as 128 polynomial
 * coefficients; `coefficientsToSlots` is the SIMD decode.
 */
import { type Hex, toHex } from 'viem'

/** Polynomial degree, and so the slot count, of the insecure SIMD preset (param set 5). */
export const DEGREE = 128
/** Plaintext modulus of the same preset: prime, 1 mod 2 * DEGREE, so it supports SIMD. */
export const PLAINTEXT_MODULUS = 257
/** The preset name the SDK and the program use. */
export const PRESET = 'INSECURE_THRESHOLD_SIMD' as const
/** Coefficients the committee publishes after decryption for this preset. */
export const OUTPUT_COEFFS = DEGREE

/** The price steps of the slot layout. A sale uses `levels` in `MIN_LEVELS..=LEVELS_MAX`. */
export const LEVELS_MAX = 16
/** The fewest price steps of a sale. */
export const MIN_LEVELS = 8
/** `w`: a budget digit is in `[0, 2^DIGIT_BITS)`. */
export const DIGIT_BITS = 2
/** `J`: the digits of a budget. */
export const LANES = 6
/** `W = DIGIT_BITS * LANES`: the bits of a budget. */
export const BUDGET_BITS = 12
/** The largest budget in budget units: `2^BUDGET_BITS - 1`. */
export const MAX_BUDGET_UNITS = 4095
/** `n`: the most bidders. `MAX_BIDDERS * (2^DIGIT_BITS - 1) = 255 <= PLAINTEXT_MODULUS - 1`. */
export const MAX_BIDDERS = 85
/** Counted flags packed in one flag cell: bidder `i` adds `2^(i % 8)` to the cell `i / 8`. */
export const FLAGS_PER_CELL = 8
/** `LEVELS_MAX * LANES`: the first flag cell. */
export const FLAG_BASE = 96
/** `ceil(MAX_BIDDERS / FLAGS_PER_CELL)`. */
export const FLAG_CELLS = 11
/** The slots in use are `0..FLAG_BASE + FLAG_CELLS`; the others are 0. */
export const SLOTS = DEGREE
/** The depth of the claim Merkle tree (128 leaves). */
export const CLAIM_TREE_DEPTH = 7
/** The escrow tiers of a sale. */
export const MAX_TIERS = 4
/** The depth of the program input tree. */
export const INPUT_TREE_DEPTH = 20

/** The first 32 bytes of the config input of an E3 (`CONFIG_DOMAIN` of the program and the contract). */
export const CONFIG_DOMAIN: Hex = toHex('interfold-token-launch-config-v1')

/** A value of the range `[0, max]`, or the error that says it is not. */
function assertInt(name: string, value: number, min: number, max: number): void {
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new Error(`${name} is an integer in [${min}, ${max}], got ${value}`)
  }
}

/** The base 4 digits of a budget, least significant first: `LANES` values in `0..4`. */
export function budgetDigits(budget: number): number[] {
  assertInt('A budget', budget, 1, MAX_BUDGET_UNITS)
  return Array.from({ length: LANES }, (_, j) => (budget >> (DIGIT_BITS * j)) & ((1 << DIGIT_BITS) - 1))
}

/** The slot of the digit `j` of the level `l`. */
export function cellSlot(level: number, lane: number): number {
  assertInt('A level', level, 0, LEVELS_MAX - 1)
  assertInt('A lane', lane, 0, LANES - 1)
  return level * LANES + lane
}

/** The SIMD slot values of a bid plaintext (the same for both E3 keys). */
export function bidSlots({ step, budget, index }: { step: number; budget: number; index: number }): BigUint64Array {
  assertInt('A step', step, 0, LEVELS_MAX - 1)
  assertInt('A bid index', index, 0, MAX_BIDDERS - 1)
  const digits = budgetDigits(budget)
  const slots = new BigUint64Array(SLOTS)
  for (let level = 0; level <= step; level++) {
    digits.forEach((digit, lane) => {
      slots[level * LANES + lane] = BigInt(digit)
    })
  }
  slots[FLAG_BASE + Math.floor(index / FLAGS_PER_CELL)] = 1n << BigInt(index % FLAGS_PER_CELL)
  return slots
}

/**
 * The 0/1 plaintext an E3 multiplies its sum with: the cells of every level in `probeMask` (bit `l`
 * for the level `l`) and all the flag cells.
 */
export function keepMask(probeMask: number): BigUint64Array {
  assertInt('A probe mask', probeMask, 0, 0xffff)
  const mask = new BigUint64Array(SLOTS)
  for (let level = 0; level < LEVELS_MAX; level++) {
    if ((probeMask >> level) & 1) mask.fill(1n, level * LANES, (level + 1) * LANES)
  }
  mask.fill(1n, FLAG_BASE, FLAG_BASE + FLAG_CELLS)
  return mask
}

/** What the decrypted output holds. */
export interface SaleOutput {
  /** `cells[l][j]`: the sum of the digit `j` over the counted bids with a step of at least `l` (0 at a level that was not kept). */
  cells: number[][]
  /** The flag cells; `countedBitmap` reads them. */
  flagCells: number[]
}

/**
 * Reads the output slots. `bidCount` is the number of bids the sale accepted: a cell is at most
 * `3 * bidCount` and a flag bit is only set for an index below `bidCount`, as `SaleOutput.sol` checks.
 */
export function decodeOutput(slots: ArrayLike<number | bigint>, bidCount: number = MAX_BIDDERS): SaleOutput {
  assertInt('The bid count', bidCount, 0, MAX_BIDDERS)
  if (slots.length !== SLOTS) throw new Error(`The output has ${SLOTS} slots, got ${slots.length}`)
  const values = Array.from(slots, (slot, i) => {
    const value = Number(slot)
    if (!Number.isInteger(value) || value < 0 || value >= PLAINTEXT_MODULUS) throw new Error(`Slot ${i} is not below ${PLAINTEXT_MODULUS}`)
    return value
  })
  const maxCell = ((1 << DIGIT_BITS) - 1) * bidCount
  const cells = Array.from({ length: LEVELS_MAX }, (_, level) => values.slice(level * LANES, (level + 1) * LANES))
  for (const cell of cells.flat()) {
    if (cell > maxCell) throw new Error(`A cell is at most ${maxCell} for ${bidCount} bids, got ${cell}`)
  }
  const flagCells = values.slice(FLAG_BASE, FLAG_BASE + FLAG_CELLS)
  const bitmap = countedBitmap(flagCells)
  if (bitmap >> BigInt(bidCount) !== 0n) throw new Error(`A counted flag is set at or above the bid count ${bidCount}`)
  return { cells, flagCells }
}

/** `F_l`: the budget sum, in budget units, of the counted bids with a step of at least `l`. */
export function levelSum(cells: readonly (readonly number[])[], level: number): bigint {
  assertInt('A level', level, 0, LEVELS_MAX - 1)
  return cells[level].reduce((sum, cell, lane) => sum + (BigInt(cell) << BigInt(DIGIT_BITS * lane)), 0n)
}

/** The counted bitmap: bit `i` is set iff the bid `i` was counted. */
export function countedBitmap(flagCells: readonly number[]): bigint {
  if (flagCells.length !== FLAG_CELLS) throw new Error(`There are ${FLAG_CELLS} flag cells, got ${flagCells.length}`)
  return flagCells.reduce((bitmap, cell, i) => {
    if (cell >= 1 << FLAGS_PER_CELL) throw new Error(`A flag cell is below ${1 << FLAGS_PER_CELL}, got ${cell}`)
    return bitmap | (BigInt(cell) << BigInt(FLAGS_PER_CELL * i))
  }, 0n)
}

/**
 * The config input of an E3: `CONFIG_DOMAIN || uint8 role || uint8 levels || uint16 probeMask` (big
 * endian). Role 1 is round 1, role 2 is round 2.
 */
export function configBytes(role: 1 | 2, levels: number, probeMask: number): Hex {
  assertInt('The role', role, 1, 2)
  assertInt('The levels', levels, MIN_LEVELS, LEVELS_MAX)
  assertInt('A probe mask', probeMask, 0, 0xffff)
  return `${CONFIG_DOMAIN}${toHex(role, { size: 1 }).slice(2)}${toHex(levels, { size: 1 }).slice(2)}${toHex(probeMask, { size: 2 }).slice(2)}`
}

// ---------------------------------------------------------------------------------------------
// SIMD slots <-> published plaintext
// ---------------------------------------------------------------------------------------------

/**
 * The evaluation point of each SIMD slot: slot `j` of a plaintext with the coefficients `a` is
 * `sum_k a[k] * POINTS[j]^k mod 257`. It is `simd_decode` of the unit polynomial `x`;
 * `test-vectors/slots.json` pins it against the fhe.rs decoder.
 */
const POINTS: readonly number[] = [
  182, 119, 10, 229, 150, 76, 20, 33, 214, 163, 40, 7, 86, 238, 80, 56, 85, 152, 160, 191, 87, 69, 63, 243, 83, 219, 126, 145, 91, 47, 252,
  132, 75, 138, 247, 28, 107, 181, 237, 224, 43, 94, 217, 250, 171, 19, 177, 201, 172, 105, 97, 66, 170, 188, 194, 14, 174, 38, 131, 112,
  166, 210, 5, 125, 233, 54, 180, 156, 12, 186, 90, 148, 251, 41, 45, 147, 3, 27, 151, 179, 127, 93, 204, 183, 65, 149, 102, 55, 96, 142,
  51, 39, 209, 175, 154, 37, 24, 203, 77, 101, 245, 71, 167, 109, 6, 216, 212, 110, 254, 230, 106, 78, 130, 164, 53, 74, 192, 108, 155, 202,
  161, 115, 206, 218, 48, 82, 103, 220,
]

const T = PLAINTEXT_MODULUS

function modPow(base: number, exp: number): number {
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
  const n = DEGREE
  const a = POINTS.map((point, j) => [
    ...Array.from({ length: n }, (_, k) => modPow(point, k)),
    ...Array.from({ length: n }, (_, k) => (k === j ? 1 : 0)),
  ])
  for (let col = 0; col < n; col++) {
    let pivot = col
    while (pivot < n && a[pivot][col] === 0) pivot++
    if (pivot === n) throw new Error('The slot matrix is singular')
    ;[a[col], a[pivot]] = [a[pivot], a[col]]
    const scale = modPow(a[col][col], T - 2)
    for (let k = 0; k < 2 * n; k++) a[col][k] = (a[col][k] * scale) % T
    for (let row = 0; row < n; row++) {
      if (row === col || a[row][col] === 0) continue
      const factor = a[row][col]
      for (let k = 0; k < 2 * n; k++) a[row][k] = (((a[row][k] - factor * a[col][k]) % T) + T) % T
    }
  }
  cachedInverse = a.map((row) => row.slice(n))
  return cachedInverse
}

/** The SIMD slots of the plaintext with the polynomial `coefficients` (what the committee publishes). */
export function coefficientsToSlots(coefficients: ArrayLike<number | bigint>): number[] {
  if (coefficients.length !== DEGREE) throw new Error(`A plaintext has ${DEGREE} coefficients, got ${coefficients.length}`)
  const a = Array.from(coefficients, Number)
  return POINTS.map((point) => {
    let acc = 0
    for (let k = DEGREE - 1; k >= 0; k--) acc = (acc * point + a[k]) % T
    return acc
  })
}

/** The coefficients of the plaintext that has the SIMD `slots` (missing slots are 0). */
export function slotsToCoefficients(slots: ArrayLike<number | bigint>): number[] {
  if (slots.length > DEGREE) throw new Error(`A plaintext has at most ${DEGREE} slots, got ${slots.length}`)
  const matrix = inverseMatrix()
  const s = Array.from(slots, Number)
  return Array.from({ length: DEGREE }, (_, k) => {
    let sum = 0
    for (let j = 0; j < s.length; j++) sum += matrix[k][j] * s[j]
    return sum % T
  })
}

/** The published plaintext bytes: 128 little-endian `uint64` coefficients, as `0x` hex. */
export function coefficientsToPlaintext(coefficients: ArrayLike<number | bigint>): Hex {
  let hex = '0x'
  for (const value of Array.from(coefficients, BigInt)) {
    hex +=
      value
        .toString(16)
        .padStart(4, '0')
        .replace(/^(..)(..)$/, '$2$1') + '00'.repeat(6)
  }
  return hex as Hex
}

/** The inverse of `coefficientsToPlaintext`. */
export function plaintextToCoefficients(plaintext: string): number[] {
  const hex = plaintext.startsWith('0x') ? plaintext.slice(2) : plaintext
  if (hex.length !== 16 * DEGREE) throw new Error(`A plaintext is ${8 * DEGREE} bytes, got ${hex.length / 2}`)
  return Array.from({ length: DEGREE }, (_, k) => {
    const word = BigInt(`0x${(hex.slice(16 * k, 16 * k + 16).match(/../g) as string[]).reverse().join('')}`)
    if (word >= BigInt(T)) throw new Error(`Coefficient ${k} is not below ${T}`)
    return Number(word)
  })
}

/** Decodes the plaintext the committee published into the output (`coefficientsToSlots`, then `decodeOutput`). */
export function decodePlaintext(plaintext: string, bidCount: number = MAX_BIDDERS): SaleOutput {
  return decodeOutput(coefficientsToSlots(plaintextToCoefficients(plaintext)), bidCount)
}
