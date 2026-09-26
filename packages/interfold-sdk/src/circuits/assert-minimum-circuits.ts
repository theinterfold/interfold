// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { SDKError } from '../utils'

// NOTE: Node.js builtins (`node:fs`, `node:path`, `node:url`) are intentionally
// NOT imported at the top level. Browser bundlers (Vite/esbuild) externalize
// them into stubs that throw the moment the module is evaluated — even behind a
// runtime `isNode` guard — because the static import binding is accessed at load
// time. They are instead imported dynamically inside the Node-only path below,
// which never executes in the browser, so browser bundles never touch them.

/** Matches `IInterfold.CommitteeSize.Minimum` and `DEFAULT_E3_CONFIG.committeeSize`. */
export const SDK_CIRCUIT_COMMITTEE = 'minimum'

// Reliable Node detection: `process.versions.node` is only set in a real Node
// runtime (not in browsers or web workers, even when `process` is polyfilled).
const isNode = typeof process !== 'undefined' && process.versions != null && process.versions.node != null

/**
 * Check the local SDK artifact selection before proof generation.
 * Browser bundles contain their artifacts and do not use the local stamp.
 * Await this check so a missing or mismatched stamp rejects the proof request.
 */
export async function assertSdkMinimumCircuits(): Promise<void> {
  if (!isNode) return
  await assertNodeCircuits()
}

async function assertNodeCircuits(): Promise<void> {
  const { existsSync, readFileSync } = await import('node:fs')
  const { dirname, resolve } = await import('node:path')
  const { fileURLToPath } = await import('node:url')

  const findActivePath = (): string | null => {
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

  let active: { committee?: string; preset?: string }
  try {
    active = JSON.parse(raw) as { committee?: string; preset?: string }
    if (active === null || typeof active !== 'object' || Array.isArray(active)) throw new Error('Invalid stamp object')
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

  if (active.preset !== 'insecure-512') {
    throw new SDKError('SDK encryption circuits require the insecure-512 preset.', 'SDK_CIRCUIT_PRESET_MISMATCH')
  }
}
