// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Circuit registry — CRISP's `setCircuits` pattern. The three compiled Noir artifacts
// (`circuits/bin/threshold/target/*.json`) are loaded by the consumer (the client fetches them
// from `/circuits/`, the node harness reads them from disk) and registered once.

import type { CompiledCircuit } from '@noir-lang/noir_js'

import type { CircuitName } from './types'

export type CircuitBundle = Record<CircuitName, CompiledCircuit>

let registered: CircuitBundle | null = null

export const setCircuits = (bundle: CircuitBundle): void => {
  registered = bundle
}

export const requireCircuits = (): CircuitBundle => {
  if (!registered) {
    throw new Error('No CKKS matching circuits registered. Load the three compiled circuits and call setCircuits() before proving.')
  }
  return registered
}
