// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Top-level Node.js imports are stubbed by bundlers (Vite/esbuild) in browser
// builds. They only execute at runtime inside the `isNode` guard below.
import { existsSync, readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { SDKError } from '../utils'

/** Matches `IInterfold.CommitteeSize.Minimum` and `DEFAULT_E3_CONFIG.committeeSize`. */
export const SDK_CIRCUIT_COMMITTEE = 'minimum'

const isNode = typeof window === 'undefined' && typeof import.meta.url !== 'undefined'

let checked = false

function findActivePath(): string | null {
  if (!import.meta.url) return null

  let dir = dirname(fileURLToPath(import.meta.url))

  while (true) {
    if (existsSync(resolve(dir, 'package.json'))) {
      const bundled = resolve(dir, '.active-preset.json')
      if (existsSync(bundled)) return bundled

      if (dir.includes('node_modules')) return null

      return resolve(dir, '../../circuits/bin/.active-preset.json')
    }

    const parent = dirname(dir)
    if (parent === dir) break
    dir = parent
  }

  throw new SDKError('Could not locate SDK package root', 'SDK_CIRCUIT_STAMP_MISSING')
}

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

  const activePresetPath = findActivePath()
  if (activePresetPath === null) return

  let raw: string
  try {
    raw = readFileSync(activePresetPath, 'utf-8')
  } catch {
    throw new SDKError(
      `Missing ${activePresetPath}. Run \`pnpm -C packages/interfold-sdk compile:circuits\` first.`,
      'SDK_CIRCUIT_STAMP_MISSING',
    )
  }

  let active: { committee?: string }
  try {
    active = JSON.parse(raw) as { committee?: string }
  } catch {
    throw new SDKError(
      `Could not parse ${activePresetPath} — run \`pnpm -C packages/interfold-sdk compile:circuits\`.`,
      'SDK_CIRCUIT_STAMP_INVALID',
    )
  }

  if (!active.committee || active.committee !== SDK_CIRCUIT_COMMITTEE) {
    throw new SDKError(
      `Active circuit committee is "${active.committee ?? 'unknown'}" but the SDK requires "${SDK_CIRCUIT_COMMITTEE}". ` +
        `Run \`pnpm build:circuits --committee ${SDK_CIRCUIT_COMMITTEE}\`.`,
      'SDK_CIRCUIT_COMMITTEE_MISMATCH',
    )
  }
}
