// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { existsSync, readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { SDKError } from '../utils'

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

/**
 * SDK encryption artifacts are built for the minimum committee preset by default.
 * Fail fast when `circuits/bin/.active-preset.json` points at another committee
 * (e.g. after benchmark runs with `--committee small`).
 */
export function checkSdkMinimumCircuits(): void {
  if (ACTIVE_PRESET_PATH === null) return

  let raw: string
  try {
    raw = readFileSync(ACTIVE_PRESET_PATH, 'utf-8')
  } catch {
    throw new SDKError(
      `Missing ${ACTIVE_PRESET_PATH}. Run \`pnpm -C packages/interfold-sdk compile:circuits\` first.`,
      'SDK_CIRCUIT_STAMP_MISSING',
    )
  }

  let active: { committee?: string }
  try {
    active = JSON.parse(raw) as { committee?: string }
  } catch {
    throw new SDKError(
      `Could not parse ${ACTIVE_PRESET_PATH} — run \`pnpm -C packages/interfold-sdk compile:circuits\`.`,
      'SDK_CIRCUIT_STAMP_INVALID',
    )
  }

  if (!active.committee || active.committee !== 'minimum') {
    throw new SDKError(
      `Active circuit committee is "${active.committee ?? 'unknown'}" but the SDK requires "minimum". ` +
        `Run \`pnpm build:circuits --committee minimum\`.`,
      'SDK_CIRCUIT_COMMITTEE_MISMATCH',
    )
  }
}
