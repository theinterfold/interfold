// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { existsSync, readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { SDKError } from '../utils'

/** Matches `IInterfold.CommitteeSize.Minimum` and `DEFAULT_E3_CONFIG.committeeSize`. */
export const SDK_CIRCUIT_COMMITTEE = 'minimum'

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

const ACTIVE_PRESET_PATH = findActivePath()

let checked = false

/**
 * SDK encryption artifacts are built for the minimum committee preset by default.
 * Fail fast when `circuits/bin/.active-preset.json` points at another committee
 * (e.g. after benchmark runs with `--committee small`).
 */
export function assertSdkMinimumCircuits(): void {
  if (checked) return

  if (ACTIVE_PRESET_PATH === null) {
    checked = true
    return
  }

  let raw: string
  try {
    raw = readFileSync(ACTIVE_PRESET_PATH, 'utf-8')
  } catch {
    throw new SDKError(
      `Missing ${ACTIVE_PRESET_PATH}. Run \`pnpm -C packages/interfold-sdk compile:circuits\` first.`,
      'SDK_CIRCUIT_STAMP_MISSING',
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
