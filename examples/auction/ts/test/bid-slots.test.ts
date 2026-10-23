// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/** Port of `tests/bid_slots.rs`: the slot plaintexts of a bid, as the bid proof circuits read them. */

import { describe, expect, it } from 'vitest'
import { newSetup } from '../src'
import { bidSlots as compactBidSlots } from '../src/designs/vickrey-compact'
import { bidSlots as thermometerBidSlots } from '../src/designs/vickrey'
import { copies, slotLevel } from '../src/designs/vickrey-common'

describe('every slot of a vickrey bid depends on its level only', () => {
  // 3 bidders at 16 levels leave 16 slots beyond the last copy of 48: they hold 0.
  for (const [bidders, levels] of [
    [4, 16],
    [3, 16],
  ]) {
    it(`${bidders} bidders, ${levels} levels`, () => {
      const setup = newSetup('toy', bidders, levels)
      const slots = copies(setup) * bidders * levels
      for (const bid of [0, 5, 15]) {
        const thermometers = thermometerBidSlots(setup, bid)
        const combined = compactBidSlots(setup, bid)
        expect([thermometers.length, combined.length]).toEqual([2, 1])
        for (let slot = 0; slot < setup.ring.degree; slot++) {
          const level = slotLevel(setup, slot)
          expect(level !== null).toBe(slot < slots)
          const atLeast = level === null ? 0 : Number(bid >= level)
          const above = level === null ? 0 : Number(bid > level)
          expect(thermometers[0][slot]).toBe(atLeast)
          expect(thermometers[1][slot]).toBe(above)
          expect(combined[0][slot]).toBe(2 * atLeast - above)
        }
      }
    })
  }
})
