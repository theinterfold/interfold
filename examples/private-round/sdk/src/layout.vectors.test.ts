// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { bidSlots, decodeRound, Outcome } from './layout'

interface Vector {
  levels: number
  reserveStep: number
  lots: number
  minLots: number
  firstBid: { level: number; bidderIndex: number; version: number; slots: number[] }
  slots: number[]
  outcome: keyof typeof Outcome
  step: number | null
  counted: number
  versions: number[]
}

// Written by the Rust program (`program/examples/layout_vectors.rs`), which owns the layout.
const path = join(dirname(fileURLToPath(import.meta.url)), '../test-vectors/layout.json')
const { cases } = JSON.parse(readFileSync(path, 'utf8')) as { cases: Vector[] }

describe('layout against the vectors of the FHE program', () => {
  it('has cases of every outcome', () => {
    expect(new Set(cases.map((vector) => vector.outcome))).toEqual(new Set(['NotMet', 'Undersubscribed', 'SoldOut', 'Aborted']))
  })

  it.each(cases.map((vector, index) => [index, vector] as const))(
    'case %i: bid slots and decoder agree with the program',
    (_index, vector) => {
      const params = { levels: vector.levels, reserveStep: vector.reserveStep, lots: vector.lots, minLots: vector.minLots }
      const { level, bidderIndex, version, slots: bid } = vector.firstBid
      expect([...bidSlots(level, params.reserveStep, bidderIndex, version)].map(Number)).toEqual(bid)

      const output = decodeRound(vector.slots.map(BigInt), params)
      expect(Outcome[output.outcome]).toBe(vector.outcome)
      expect(output.step).toBe(vector.step)
      expect(output.counted).toBe(vector.counted)
      expect(output.versions).toEqual(vector.versions)
    },
  )
})
