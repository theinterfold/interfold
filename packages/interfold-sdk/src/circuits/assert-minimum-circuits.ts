// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/** Matches `IInterfold.CommitteeSize.Minimum` and `DEFAULT_E3_CONFIG.committeeSize`. */
export const SDK_CIRCUIT_COMMITTEE = 'minimum'

// Node-only circuit check — in the browser this is a no-op.
const isNode = typeof window === 'undefined' && typeof import.meta.url !== 'undefined'

let checked = false

/**
 * SDK encryption artifacts are built for the minimum committee preset by default.
 * Fail fast when `circuits/bin/.active-preset.json` points at another committee
 * (e.g. after benchmark runs with `--committee small`).
 *
 * In browser environments this is a no-op (circuit files don't exist client-side).
 */
export function assertSdkMinimumCircuits(): void {
  if (checked || !isNode) {
    checked = true
    return
  }
  checked = true

  // Dynamic import so bundlers can tree-shake Node APIs from browser bundles.
  import('./assert-minimum-circuits-node').then(
    (m) => m.checkSdkMinimumCircuits(),
    (err) => {
      throw err
    },
  )
}
    )
  }

  let committee: string | undefined
  try {
    committee = JSON.parse(raw)?.committee as string | undefined
  } catch {
    throw new SDKError(
      `Invalid JSON in ${ACTIVE_PRESET_PATH}. Rebuild with \`pnpm -C packages/interfold-sdk compile:circuits\`.`,
      'SDK_CIRCUIT_STAMP_INVALID',
    )
  }

  if (committee !== SDK_CIRCUIT_COMMITTEE) {
    throw new SDKError(
      `SDK requires circuits built for committee "${SDK_CIRCUIT_COMMITTEE}" ` +
        `(active preset is "${committee ?? 'unknown'}"). ` +
        `Run: pnpm -C packages/interfold-sdk compile:circuits`,
      'SDK_CIRCUIT_COMMITTEE_MISMATCH',
    )
  }

  checked = true
}
