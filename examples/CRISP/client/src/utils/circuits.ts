// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { registeredPreset, setCircuits } from '@crisp-e3/sdk'
import type { CircuitBundle, CircuitPreset } from '@crisp-e3/sdk'

// The BFV-shaped circuits ship as their own entry point per preset. Loading them
// through a dynamic import gives the bundler a split point, so the app boots on the ~350KB main
// entry and only pays for the circuits when someone actually votes.
//
// The production SDK carries both presets. The E3 stores the selected param set on chain, so the
// client selects the matching circuits before proving instead of hardcoding one deployment mode.
const LOADERS: Record<CircuitPreset, () => Promise<{ loadCircuits: () => Promise<CircuitBundle> }>> = {
  'insecure-512': () => import('@crisp-e3/sdk/insecure-512'),
  'secure-8192': () => import('@crisp-e3/sdk/secure-8192'),
}

let pending: Partial<Record<CircuitPreset, Promise<void>>> = {}

const presetForParamSet = (paramSet: number): CircuitPreset | null => {
  if (paramSet === 0) return 'insecure-512'
  if (paramSet === 2) return 'secure-8192'
  return null
}

/** Install the circuits needed for proving, at most once per session. */
export const ensureCircuits = async (paramSet: number): Promise<void> => {
  const expectedPreset = presetForParamSet(paramSet)
  if (!expectedPreset) {
    throw new Error(`Unsupported E3 param set ${paramSet}.`)
  }

  const activePreset = registeredPreset()
  if (activePreset === expectedPreset) {
    return
  }

  const load = (pending[expectedPreset] ??= (async () => {
    const { loadCircuits } = await LOADERS[expectedPreset]()
    setCircuits(await loadCircuits())
  })())

  try {
    await load
  } finally {
    // Cache only in-flight loads. A later preset switch must rerun setCircuits().
    if (pending[expectedPreset] === load) {
      delete pending[expectedPreset]
    }
  }

  if (registeredPreset() !== expectedPreset) {
    throw new Error(`The loaded circuit bundle does not match E3 param set ${paramSet}.`)
  }
}
