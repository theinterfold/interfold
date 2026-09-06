// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { CreditApi, setCircuits } from '@ckks-credit/sdk'
import type { CircuitBundle } from '@ckks-credit/sdk'
import { CIRCUIT_NAMES } from '@ckks-credit/sdk'

export const API_URL = import.meta.env.VITE_CREDIT_API ?? 'http://127.0.0.1:8092'
export const api = new CreditApi(API_URL)

let circuitsLoaded: Promise<void> | null = null

/** Loads the three compiled Noir circuits from `/circuits/` (served from `circuits/bin/threshold/target`). */
export const ensureCircuits = (): Promise<void> => {
  circuitsLoaded ??= (async () => {
    const entries = await Promise.all(
      (Object.entries(CIRCUIT_NAMES) as [keyof CircuitBundle, string][]).map(async ([leg, name]) => {
        const res = await fetch(`/circuits/${name}.json`)
        if (!res.ok) throw new Error(`could not load circuit ${name}: ${res.status}`)
        return [leg, await res.json()] as const
      }),
    )
    setCircuits(Object.fromEntries(entries) as CircuitBundle)
  })()
  return circuitsLoaded
}
