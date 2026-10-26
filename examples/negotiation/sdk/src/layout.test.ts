// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import {
  combineOffers,
  DEGREE,
  expectedOutcome,
  gridFor,
  GROUPS,
  LANES,
  laneSlots,
  LEVELS,
  levelSums,
  maskSlots,
  offerSlots,
  PLAINTEXT_MODULUS,
  readOutputSlots,
  Role,
  stepFor,
  tensorEntry,
} from './layout'
import { buyerPosterior, likelihood, metrics, sellerPosterior } from './uniformity'

const VECTORS = join(dirname(fileURLToPath(import.meta.url)), '..', 'test-vectors', 'layout.json')

/** A fixed pseudo-random stream, so that the test vectors do not change between runs. */
function seeded(seed: number): () => number {
  let state = seed >>> 0
  return () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0
    return state % Number(PLAINTEXT_MODULUS)
  }
}

describe('lane tensor', () => {
  it('sums to the one-hot of the least l xor u in [s, b] (exhaustive over s, b, a, c)', () => {
    // entry[step][share][theta][i], computed once for each role.
    const table = (role: Role) =>
      Array.from({ length: LEVELS }, (_, step) =>
        Array.from({ length: LANES }, (_, share) =>
          Array.from({ length: LANES }, (_, theta) => Array.from({ length: LEVELS }, (_, i) => tensorEntry(role, theta, i, step, share))),
        ),
      )
    const seller = table(Role.Seller)
    const buyer = table(Role.Buyer)
    for (let s = 0; s < LEVELS; s++) {
      for (let b = 0; b < LEVELS; b++) {
        for (let a = 0; a < LANES; a++) {
          for (let c = 0; c < LANES; c++) {
            const winner = expectedOutcome(s, b, a, c)
            for (let i = 0; i < LEVELS; i++) {
              let sum = 0
              for (let theta = 0; theta < LANES; theta++) sum += seller[s][a][theta][i] * buyer[b][c][theta][i]
              expect(sum).toBe(winner.step === i ? 1 : 0)
            }
          }
        }
      }
    }
  })

  it('puts lanes 0..7 in the first ciphertext and 8..15 in the second', () => {
    const [low, high] = laneSlots(Role.Seller, 3, 5)
    for (let theta = 0; theta < LANES; theta++) {
      for (let i = 0; i < LEVELS; i++) {
        const slots = theta < 8 ? low : high
        expect(slots[(theta & 7) * LEVELS + i]).toBe(BigInt(tensorEntry(Role.Seller, theta, i, 3, 5)))
      }
    }
  })
})

describe('mask', () => {
  it('has a zero sum over the groups of every level', () => {
    const mask = maskSlots()
    for (const level of levelSums(mask)) expect(level).toBe(0n)
  })
})

describe('combined output', () => {
  it('matches: the level sums are the one-hot of the agreed level', () => {
    const output = combineOffers(offerSlots(Role.Seller, 2, 9), offerSlots(Role.Buyer, 12, 6))
    const outcome = readOutputSlots(output)
    expect(outcome).toEqual(expectedOutcome(2, 12, 9, 6))
    expect(outcome.matched).toBe(true)
  })

  it('does not match when the buyer step is below the seller step', () => {
    const output = combineOffers(offerSlots(Role.Seller, 9, 1), offerSlots(Role.Buyer, 4, 14))
    expect(readOutputSlots(output)).toEqual({ matched: false, step: null })
  })

  it('rejects an output that is not a valid outcome', () => {
    const slots = new BigUint64Array(DEGREE)
    slots[0] = 1n
    slots[1] = 1n
    expect(() => readOutputSlots(slots)).toThrow('not a valid outcome')
    slots[1] = 0n
    slots[16] = 2n
    expect(() => readOutputSlots(slots)).toThrow('not a valid outcome')
  })

  it('hides the lane: every group of the winning level holds a mask value, not the lane', () => {
    // Without the mask, one lane of the winning level is 1 and the others are 0. With both masks, the 8 group
    // values of each level are uniform subject to the sum (here: not all but one group are 0 for any level).
    const output = combineOffers(offerSlots(Role.Seller, 2, 9, maskSlots(seeded(1))), offerSlots(Role.Buyer, 12, 6, maskSlots(seeded(2))))
    for (let i = 0; i < LEVELS; i++) {
      let nonZero = 0
      for (let g = 0; g < GROUPS; g++) if (output[g * LEVELS + i] !== 0n) nonZero++
      expect(nonZero).toBeGreaterThan(4)
    }
  })

  it('writes and checks the shared test vectors', () => {
    const cases = [
      [2, 9, 12, 6],
      [0, 0, 15, 15],
      [5, 3, 5, 12],
      [7, 14, 7, 14],
      [9, 1, 4, 14],
      [0, 5, 15, 10],
      [15, 8, 15, 3],
      [14, 2, 15, 2],
    ].map(([sellerStep, sellerShare, buyerStep, buyerShare], index) => {
      const sellerOffer = offerSlots(Role.Seller, sellerStep, sellerShare, maskSlots(seeded(2 * index + 1)))
      const buyerOffer = offerSlots(Role.Buyer, buyerStep, buyerShare, maskSlots(seeded(2 * index + 2)))
      const output = combineOffers(sellerOffer, buyerOffer)
      const outcome = readOutputSlots(output)
      return {
        sellerStep,
        sellerShare,
        buyerStep,
        buyerShare,
        seller: sellerOffer.map((slots) => Array.from(slots, Number)),
        buyer: buyerOffer.map((slots) => Array.from(slots, Number)),
        output: Array.from(output, Number),
        matched: outcome.matched,
        step: outcome.step,
      }
    })
    if (process.env.UPDATE_VECTORS === '1' || !existsSync(VECTORS)) writeFileSync(VECTORS, `${JSON.stringify({ cases }, null, 2)}\n`)
    expect(JSON.parse(readFileSync(VECTORS, 'utf8')).cases).toEqual(cases)
  })
})

describe('price grid', () => {
  it('maps a public range to levels', () => {
    expect(gridFor(48n, 63n, 1n)).toEqual({ levels: 16 })
    expect(gridFor(0n, 100n, 10n)).toEqual({ levels: 11 })
    expect(gridFor(0n, 100n, 7n)).toHaveProperty('error')
    expect(gridFor(0n, 100n, 1n)).toHaveProperty('error')
    expect(stepFor(60n, 48n, 1n, 16)).toBe(12)
    expect(stepFor(64n, 48n, 1n, 16)).toHaveProperty('error')
  })
})

describe('uniformity', () => {
  const table = likelihood(LEVELS)

  it('is a law on every interval', () => {
    for (let s = 0; s < LEVELS; s++) {
      for (let b = s; b < LEVELS; b++) {
        expect(table[s][b].reduce((a, v) => a + v, 0)).toBeCloseTo(1, 12)
        for (let p = 0; p < LEVELS; p++) if (p < s || p > b) expect(table[s][b][p]).toBe(0)
      }
    }
  })

  it('matches the documented figures', () => {
    const m = metrics(table)
    expect(m.excluded).toBe(0)
    expect(m.maxTv).toBeCloseTo(0.4167, 3)
    expect(m.meanTv).toBeCloseTo(0.1444, 3)
    expect(m.overweight).toBeCloseTo(4.5, 6)
    expect(m.underweight).toBeCloseTo(0.375, 6)
    expect(m.mutualInformation - m.idealMutualInformation).toBeCloseTo(0.1198, 3)
  })

  it('leaks no more than an upper bound on b to the seller, and a lower bound on s to the buyer', () => {
    const posterior = sellerPosterior(table, LEVELS, 2, 7)
    for (let b = 0; b < 7; b++) expect(posterior[b]).toBe(0)
    expect(posterior.slice(7).every((v) => v > 0)).toBe(true)
    const buyer = buyerPosterior(table, LEVELS, 12, 7)
    for (let s = 8; s <= 12; s++) expect(buyer[s]).toBe(0)
    expect(buyer.slice(0, 8).every((v) => v > 0)).toBe(true)
  })
})
