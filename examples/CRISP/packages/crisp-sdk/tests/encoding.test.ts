// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { afterEach, beforeAll, describe, expect, it } from 'vitest'

import { setCircuits } from '../src/circuits'
import { getZkInputsGenerator, setZkInputsGeneratorPreset } from '../src/encoding'
import { loadCircuits } from '../src/presets/insecure'

beforeAll(async () => {
  setCircuits(await loadCircuits())
})

afterEach(() => {
  setZkInputsGeneratorPreset(null)
})

describe('ZK inputs generator preset', () => {
  it('clears a worker override when the next request has no preset', () => {
    setZkInputsGeneratorPreset('secure-8192')
    expect(getZkInputsGenerator().getBFVParams().degree).toBe(8192)

    setZkInputsGeneratorPreset(null)
    expect(getZkInputsGenerator().getBFVParams().degree).toBe(128)
  })
})
