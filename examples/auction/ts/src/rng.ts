// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/** The random source of a simulated bidder or of the tie draw. */
export interface Rng {
  /** A uniform integer in `lo..hi` (`hi` excluded). */
  range(lo: number, hi: number): number
}

/**
 * A seeded deterministic generator (mulberry32). Use it for tests and repeatable runs. It is NOT
 * a cryptographic generator: the masks of a real bidder come from a secure source.
 */
export function seededRng(seed: number): Rng {
  let state = seed >>> 0
  const next = (): number => {
    state = (state + 0x6d2b79f5) >>> 0
    let x = state
    x = Math.imul(x ^ (x >>> 15), x | 1)
    x ^= x + Math.imul(x ^ (x >>> 7), x | 61)
    return ((x ^ (x >>> 14)) >>> 0) / 2 ** 32
  }
  return {
    range: (lo, hi) => lo + Math.floor(next() * (hi - lo)),
  }
}

/** A uniform random permutation of `0..n` (Fisher-Yates). */
export function shuffledIndices(n: number, rng: Rng): number[] {
  const order = Array.from({ length: n }, (_, i) => i)
  for (let i = n - 1; i > 0; i--) {
    const j = rng.range(0, i + 1)
    ;[order[i], order[j]] = [order[j], order[i]]
  }
  return order
}

/** N uniform values in `0..t`. */
export function uniformSlots(degree: number, t: number, rng: Rng): number[] {
  return Array.from({ length: degree }, () => rng.range(0, t))
}
