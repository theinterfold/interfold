// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { describe, expect, it } from 'vitest'

import { keeperStep, roundTwoGate, SalePhase } from './phases'

describe('SalePhase', () => {
  it('has the order of ITokenLaunch.Phase', () => {
    expect(SalePhase).toMatchObject({ None: 0, Bidding: 1, Round1: 2, Probing: 3, Round2: 4, Clearable: 5, Cleared: 6, Aborted: 7, Failed: 8 })
  })
})

describe('keeperStep', () => {
  it('publishes the probes once round 1 has its plaintext and clears once round 2 has its plaintext', () => {
    expect(keeperStep(SalePhase.Probing)).toBe('publishProbes')
    expect(keeperStep(SalePhase.Clearable)).toBe('clear')
  })

  it('settles a cleared sale, whose marginal claims may still need a payment', () => {
    expect(keeperStep(SalePhase.Cleared)).toBe('settle')
  })

  it('waits while the committee works or the window is open', () => {
    for (const phase of [SalePhase.Bidding, SalePhase.Round1, SalePhase.Round2]) expect(keeperStep(phase)).toBe('wait')
  })

  it('is done with a sale that was aborted or failed', () => {
    for (const phase of [SalePhase.Aborted, SalePhase.Failed]) expect(keeperStep(phase)).toBe('done')
  })
})

describe('roundTwoGate', () => {
  it('opens only after the probes are published', () => {
    expect(roundTwoGate(SalePhase.Round2)).toBe('ready')
    for (const phase of [SalePhase.Bidding, SalePhase.Round1, SalePhase.Probing]) expect(roundTwoGate(phase)).toBe('wait')
  })

  it('never opens once the output of round 2 is out or the sale ended', () => {
    for (const phase of [SalePhase.Clearable, SalePhase.Cleared, SalePhase.Aborted, SalePhase.Failed]) {
      expect(roundTwoGate(phase)).toBe('never')
    }
  })
})
