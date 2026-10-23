// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * Arithmetic in the plaintext ring `Z_t[X]/(X^N + 1)`, and the parameter profiles.
 *
 * A BFV plaintext is a polynomial with N coefficients mod t. When `t ≡ 1 (mod 2N)` is prime, the
 * ring splits into N independent slots: slot `k` is `P(α_k) mod t`, where `α_k` is a root of
 * `X^N + 1`. A sum or a product of two plaintexts acts on each slot alone. The designs use this
 * in two ways:
 *
 * - Slot designs (`first-price`, `vickrey`, ...) put one value in each slot and read slots.
 * - Coefficient designs (`rank`, `rank-batched`) put a bid in the exponent of `X^b`. A product of
 *   polynomials is a slot-wise product here too, and the design reads coefficients.
 *
 * This simulation keeps every value as its N slots. A polynomial is moved to slots with
 * `Ring.toSlots` and back with `Ring.toCoefficients`.
 *
 * The slot order here is `α_k = ψ^(2k + 1)` for one fixed `ψ`. The order of fhe.rs is a different
 * permutation. A design only uses the order to place values in slots, so the order does not
 * change any result.
 *
 * All values are JS numbers. The product of two values below t must stay below 2^53, so t must be
 * below 2^26. Both profiles are far below that limit.
 */

/** The N slot values of one plaintext or ciphertext, each in `0..t`. */
export type Slots = number[]

/** The slot-wise sum mod t. */
export function add(a: Slots, b: Slots, t: number): Slots {
  return a.map((x, k) => (x + b[k]) % t)
}

/** The slot-wise difference mod t. */
export function sub(a: Slots, b: Slots, t: number): Slots {
  return a.map((x, k) => (x - b[k] + t) % t)
}

/** The slot-wise negation mod t. */
export function neg(a: Slots, t: number): Slots {
  return a.map((x) => (x === 0 ? 0 : t - x))
}

/** ct×pt: the slot-wise product mod t. The `Evaluator` counts it as a plaintext product. */
export function mulPlain(a: Slots, b: Slots, t: number): Slots {
  return a.map((x, k) => (x * b[k]) % t)
}

/** ct×ct: the slot-wise product mod t. The `Evaluator` counts it and adds 1 to the depth. */
export function mulCipher(a: Slots, b: Slots, t: number): Slots {
  return a.map((x, k) => (x * b[k]) % t)
}

/** A half-open range `[start, end)` of slot or coefficient indices. */
export type Range = readonly [start: number, end: number]

/** `base^exponent mod t` by square and multiply. */
export function powMod(base: number, exponent: number, t: number): number {
  let result = 1
  let b = base % t
  let e = exponent
  while (e > 0) {
    if (e % 2 === 1) result = (result * b) % t
    b = (b * b) % t
    e = Math.floor(e / 2)
  }
  return result
}

/** Inverse of a non-zero `value` mod the prime `t`. */
export function inverse(value: number, t: number): number {
  return powMod(value, t - 2, t)
}

/** BFV parameter profiles. Both use a prime `t ≡ 1 (mod 2N)`. */
export type Profile = 'toy' | 'demo'

export const PROFILES: Record<Profile, { degree: number; plaintextModulus: number }> = {
  /** N = 1024, t = 12289. Fast and NOT secure: use it for tests and quick runs. */
  toy: { degree: 1024, plaintextModulus: 12289 },
  /** N = 16384, t = 65537. The ring size of the secure l-BFV preset. */
  demo: { degree: 16384, plaintextModulus: 65537 },
}

/**
 * Upper bound on log2(q) for 128-bit security at this degree, as `search_params` computes it
 * (`log2(B) + (N - 75) / 37.5` with B = 20). The toy profile is insecure by design: `null`.
 */
export function securityLimitBits(profile: Profile): number | null {
  return profile === 'toy' ? null : Math.log2(20) + (16384 - 75) / 37.5
}

/**
 * The ciphertext modulus size that a circuit of `depth` ct×ct products needs. This simulation
 * has no ciphertext modulus. It uses the number only to refuse a depth that the real profile
 * cannot hold, as the Rust crate does.
 */
export function requiredLog2q(depth: number): number {
  return 221.6 + 49.3 * Math.max(depth - 2, 0)
}

const profileRings = new Map<Profile, Ring>()

/** The ring `Z_t[X]/(X^N + 1)` with its slot structure. */
export class Ring {
  readonly degree: number
  readonly t: number
  /** ψ: a primitive 2N-th root of unity mod t. Slot k is the value at `ψ^(2k + 1)`. */
  private readonly psi: number
  private readonly psiPowers: number[]
  private readonly psiInversePowers: number[]
  private readonly omegaTables: number[][]
  private readonly omegaInverseTables: number[][]
  private readonly degreeInverse: number

  constructor(degree: number, t: number) {
    if (t >= 2 ** 26) throw new Error(`t = ${t} is too large: products must stay below 2^53`)
    if ((degree & (degree - 1)) !== 0) throw new Error(`the degree ${degree} is not a power of 2`)
    if ((t - 1) % (2 * degree) !== 0) throw new Error(`t = ${t} is not 1 mod 2N = ${2 * degree}`)
    this.degree = degree
    this.t = t
    this.psi = findPrimitiveRoot(2 * degree, t)
    const psiInverse = inverse(this.psi, t)
    this.psiPowers = powers(this.psi, degree, t)
    this.psiInversePowers = powers(psiInverse, degree, t)
    const omega = (this.psi * this.psi) % t
    this.omegaTables = rootTables(omega, degree, t)
    this.omegaInverseTables = rootTables(inverse(omega, t), degree, t)
    this.degreeInverse = inverse(degree, t)
  }

  /** The profile ring. The tables are built once for each profile. */
  static fromProfile(profile: Profile): Ring {
    let ring = profileRings.get(profile)
    if (ring === undefined) {
      const { degree, plaintextModulus } = PROFILES[profile]
      ring = new Ring(degree, plaintextModulus)
      profileRings.set(profile, ring)
    }
    return ring
  }

  /** N slots, all 0. */
  zeros(): Slots {
    return new Array<number>(this.degree).fill(0)
  }

  /** Every slot equal to `value`. */
  constant(value: number): Slots {
    return new Array<number>(this.degree).fill(value % this.t)
  }

  /** 1 in the slots of `ranges` and 0 elsewhere. */
  onesIn(ranges: Iterable<Range>): Slots {
    const slots = this.zeros()
    for (const [start, end] of ranges) slots.fill(1, start, end)
    return slots
  }

  /** The points `α_k` with `slot k = P(α_k) mod t`. */
  slotPoints(): number[] {
    return this.psiPowers.map((_, k) => powMod(this.psi, 2 * k + 1, this.t))
  }

  /** The slots of the polynomial with these N coefficients. */
  toSlots(coefficients: number[]): Slots {
    const twisted = coefficients.map((c, j) => (c * this.psiPowers[j]) % this.t)
    return cyclicTransform(twisted, this.omegaTables, this.t)
  }

  /** The N coefficients of the polynomial with these slots. Coefficient 0 is `N⁻¹ · Σ slots`. */
  toCoefficients(slots: Slots): number[] {
    const scaled = cyclicTransform(slots, this.omegaInverseTables, this.t)
    return scaled.map((x, j) => (((x * this.degreeInverse) % this.t) * this.psiInversePowers[j]) % this.t)
  }

  /**
   * Coefficients of `X^exponent` in `Z_t[X]/(X^N + 1)`, for `-N < exponent < N`.
   * `X^-k = -X^(N-k)` because `X^N = -1`.
   */
  monomial(exponent: number): number[] {
    const coefficients = this.zeros()
    if (exponent >= 0) {
      coefficients[exponent] = 1
    } else {
      coefficients[this.degree + exponent] = this.t - 1
    }
    return coefficients
  }

  /**
   * `P(point) mod t` by Horner's rule: N multiplications mod t. This is the work that a contract
   * does to check one slot of the published plaintext.
   */
  evaluate(coefficients: number[], point: number): number {
    let acc = 0
    for (let j = coefficients.length - 1; j >= 0; j--) {
      acc = (acc * point + coefficients[j]) % this.t
    }
    return acc
  }

  /**
   * The sum of all slots mod t, from coefficient 0 alone: `N · c0 = Σ slots`. The designs place
   * their result there and mask every other coefficient or make it a function of the result.
   */
  slotSum(coefficientZero: number): number {
    return (coefficientZero * this.degree) % this.t
  }
}

/** `[1, g, g^2, ..., g^(count-1)]` mod t. */
function powers(g: number, count: number, t: number): number[] {
  const result = new Array<number>(count)
  let value = 1
  for (let j = 0; j < count; j++) {
    result[j] = value
    value = (value * g) % t
  }
  return result
}

/** A primitive `order`-th root of unity mod the prime `t`, with `order` a power of 2. */
function findPrimitiveRoot(order: number, t: number): number {
  for (let g = 2; g < t; g++) {
    const root = powMod(g, (t - 1) / order, t)
    // The order is exactly `order` when root^(order/2) = -1.
    if (powMod(root, order / 2, t) === t - 1) return root
  }
  throw new Error(`no primitive ${order}-th root of unity mod ${t}`)
}

/** For each stage `len = 2, 4, ..., N` of the FFT: the powers of the `len`-th root of unity. */
function rootTables(omega: number, degree: number, t: number): number[][] {
  const tables: number[][] = []
  for (let len = 2; len <= degree; len *= 2) {
    tables.push(powers(powMod(omega, degree / len, t), len / 2, t))
  }
  return tables
}

/** `X[k] = Σ_j x[j] ω^(jk) mod t`: an iterative radix-2 transform with ω of order N. */
function cyclicTransform(input: number[], tables: number[][], t: number): number[] {
  const n = input.length
  const a = new Array<number>(n)
  // Bit-reversal permutation.
  const bits = Math.log2(n)
  for (let i = 0; i < n; i++) {
    let reversed = 0
    for (let b = 0; b < bits; b++) reversed |= ((i >> b) & 1) << (bits - 1 - b)
    a[reversed] = input[i]
  }
  let stage = 0
  for (let len = 2; len <= n; len *= 2, stage++) {
    const half = len / 2
    const twiddles = tables[stage]
    for (let start = 0; start < n; start += len) {
      for (let j = 0; j < half; j++) {
        const u = a[start + j]
        const v = (a[start + j + half] * twiddles[j]) % t
        a[start + j] = (u + v) % t
        a[start + j + half] = (u - v + t) % t
      }
    }
  }
  return a
}
