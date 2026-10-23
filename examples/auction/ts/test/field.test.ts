// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * The ring arithmetic that every design stands on. The coefficient designs (`rank`,
 * `rank-batched`) are right only if a slot-wise product is the polynomial product mod `X^N + 1`,
 * and the slot designs read coefficient 0 as `N⁻¹ · Σ slots`.
 */

import { describe, expect, it } from 'vitest'
import { add, mulCipher, mulPlain, neg, powMod, PROFILES, Ring, seededRng, sub, uniformSlots } from '../src'

/** The schoolbook product in `Z_t[X]/(X^N + 1)`: the reference for the slot-wise product. */
function negacyclicProduct(a: number[], b: number[], t: number): number[] {
  const n = a.length
  const product = new Array<number>(n).fill(0)
  for (let i = 0; i < n; i++) {
    for (let j = 0; j < n; j++) {
      const term = (a[i] * b[j]) % t
      const k = i + j
      // X^N = -1: a term past the degree wraps around with a minus sign.
      if (k < n) product[k] = (product[k] + term) % t
      else product[k - n] = (product[k - n] - term + t) % t
    }
  }
  return product
}

describe('slot-wise arithmetic mod t', () => {
  const t = 12289
  it('wraps sums, differences, negations, and products mod t', () => {
    expect(add([12288, 5], [2, 7], t)).toEqual([1, 12])
    expect(sub([1, 5], [2, 5], t)).toEqual([12288, 0])
    expect(neg([0, 1, 12288], t)).toEqual([0, 12288, 1])
    expect(mulCipher([12288, 100], [12288, 200], t)).toEqual([1, 20000 % t])
    expect(mulPlain([3, 4], [5, 0], t)).toEqual([15, 0])
  })
})

describe('the slots of a polynomial', () => {
  for (const profile of ['toy', 'demo'] as const) {
    const ring = Ring.fromProfile(profile)
    const { degree, t } = ring

    it(`${profile}: the profile is N = ${PROFILES[profile].degree}, t ≡ 1 mod 2N`, () => {
      expect(ring.degree).toBe(PROFILES[profile].degree)
      expect(ring.t).toBe(PROFILES[profile].plaintextModulus)
      expect((t - 1) % (2 * degree)).toBe(0)
    })

    it(`${profile}: slot k is the polynomial at point α_k, and the points are the roots of X^N + 1`, () => {
      const rng = seededRng(1)
      const coefficients = uniformSlots(degree, t, rng)
      const slots = ring.toSlots(coefficients)
      const points = ring.slotPoints()
      for (const k of [0, 1, 2, 7, degree - 1]) {
        expect(slots[k]).toBe(ring.evaluate(coefficients, points[k]))
        // α^N = -1, so α is a root of X^N + 1.
        expect(powMod(points[k], degree, t)).toBe(t - 1)
      }
      expect(new Set(points).size).toBe(degree)
    })

    it(`${profile}: toCoefficients undoes toSlots`, () => {
      const coefficients = uniformSlots(degree, t, seededRng(2))
      expect(ring.toCoefficients(ring.toSlots(coefficients))).toEqual(coefficients)
    })

    it(`${profile}: coefficient 0 is the sum of the slots over N`, () => {
      const slots = uniformSlots(degree, t, seededRng(3))
      const sum = slots.reduce((acc, x) => (acc + x) % t, 0)
      expect(ring.slotSum(ring.toCoefficients(slots)[0])).toBe(sum)
    })
  }

  it('toy: the slot-wise product is the polynomial product mod X^N + 1', () => {
    const ring = Ring.fromProfile('toy')
    const rng = seededRng(4)
    const a = uniformSlots(ring.degree, ring.t, rng)
    const b = uniformSlots(ring.degree, ring.t, rng)
    const viaSlots = ring.toCoefficients(mulCipher(ring.toSlots(a), ring.toSlots(b), ring.t))
    expect(viaSlots).toEqual(negacyclicProduct(a, b, ring.t))
  })

  it('toy: X^a · X^-b is X^(a-b), also across the wrap X^N = -1', () => {
    const ring = Ring.fromProfile('toy')
    for (const [a, b] of [
      [5, 2],
      [2, 5],
      [3, 3],
      [0, 7],
    ]) {
      const product = mulCipher(ring.toSlots(ring.monomial(a)), ring.toSlots(ring.monomial(-b)), ring.t)
      expect(ring.toCoefficients(product)).toEqual(ring.monomial(a - b))
    }
    // X^(N-1) · X^2 = X^(N+1) = -X.
    const wrapped = mulCipher(ring.toSlots(ring.monomial(ring.degree - 1)), ring.toSlots(ring.monomial(2)), ring.t)
    expect(ring.toCoefficients(wrapped)).toEqual(ring.monomial(1).map((c) => (c === 0 ? 0 : ring.t - 1)))
  })
})
