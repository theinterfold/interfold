// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * Checks that the committed contract artifacts match a fresh contract build.
 *
 * `crates/cli/src/ciphernode/context.rs` generates its contract bindings with `sol!` from the
 * artifact JSONs that git tracks under `packages/interfold-contracts/artifacts/`. A contract change
 * that does not regenerate them leaves the CLI calling an ABI the contract no longer has, and
 * nothing else compares the two.
 *
 * `pnpm evm:build` writes the fresh artifacts over the tracked files. This check compares the `abi`
 * of each tracked artifact at `HEAD` with the file in the working tree, entry by entry. Formatting
 * and metadata differences do not count; a function, event or error that is added, removed or
 * changed does. The fix is to commit the regenerated artifacts.
 *
 * Run after `pnpm evm:build`: `pnpm check:bindings`
 */

import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const ARTIFACTS = 'packages/interfold-contracts/artifacts'

type AbiEntry = { type: string; name?: string; inputs?: unknown; outputs?: unknown; stateMutability?: string }

function trackedArtifacts(): string[] {
  const out = execFileSync('git', ['ls-files', '-z', '--', ARTIFACTS], { cwd: REPO_ROOT, encoding: 'utf8' })
  return out.split('\0').filter((file) => file.endsWith('.json'))
}

function committedAbi(file: string): AbiEntry[] {
  const content = execFileSync('git', ['show', `HEAD:${file}`], { cwd: REPO_ROOT, encoding: 'utf8' })
  return JSON.parse(content).abi ?? []
}

function builtAbi(file: string): AbiEntry[] | undefined {
  const full = path.join(REPO_ROOT, file)
  if (!fs.existsSync(full)) return undefined
  return JSON.parse(fs.readFileSync(full, 'utf8')).abi ?? []
}

/** One stable line per ABI entry, independent of key order and formatting. */
function canonical(entry: AbiEntry): string {
  const sortKeys = (value: unknown): unknown => {
    if (Array.isArray(value)) return value.map(sortKeys)
    if (value && typeof value === 'object') {
      return Object.fromEntries(
        Object.entries(value as Record<string, unknown>)
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([key, inner]) => [key, sortKeys(inner)]),
      )
    }
    return value
  }
  return JSON.stringify(sortKeys(entry))
}

function label(entry: AbiEntry): string {
  return `${entry.type} ${entry.name ?? ''}`.trim()
}

let drift = 0
for (const file of trackedArtifacts()) {
  const built = builtAbi(file)
  if (built === undefined) {
    console.error(`${file}: tracked, but the build did not produce it. Run \`pnpm evm:build\`, or remove the file and its binding.`)
    drift += 1
    continue
  }
  const before = new Map(committedAbi(file).map((entry) => [canonical(entry), entry]))
  const after = new Map(built.map((entry) => [canonical(entry), entry]))
  const removed = [...before.keys()].filter((key) => !after.has(key)).map((key) => label(before.get(key)!))
  const added = [...after.keys()].filter((key) => !before.has(key)).map((key) => label(after.get(key)!))
  if (removed.length === 0 && added.length === 0) continue
  drift += 1
  console.error(`${file}: the committed ABI differs from the build.`)
  for (const name of removed) console.error(`  only in the committed artifact: ${name}`)
  for (const name of added) console.error(`  only in the build: ${name}`)
}

if (drift > 0) {
  console.error(`\ncheck-cli-bindings: ${drift} artifact(s) drifted. Commit the regenerated files under ${ARTIFACTS}.`)
  process.exit(1)
}
console.log('check-cli-bindings: the committed contract artifacts match the build')
