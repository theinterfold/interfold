// SPDX-License-Identifier: LGPL-3.0-only

import { execFileSync } from 'node:child_process'
import { readFileSync, realpathSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

export function syncSnapshot(path, metadata, check = false) {
  const expected = `${JSON.stringify(metadata, null, 2)}\n`
  let current
  try {
    current = readFileSync(path, 'utf8')
  } catch (error) {
    if (error.code !== 'ENOENT') throw error
  }
  if (current === expected) return
  if (check) throw new Error(`${path} is missing or stale; run the repository build or pnpm generate:crypto-bindings`)
  writeFileSync(path, expected)
}

if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2)
    if (args.length > 1 || (args.length === 1 && args[0] !== '--check')) throw new Error('Usage: crypto-config.mjs [--check]')
    const root = fileURLToPath(new URL('../..', import.meta.url))
    const metadata = JSON.parse(
      execFileSync('cargo', ['run', '--quiet', '--locked', '-p', 'e3-zk-build', '--', 'export-config'], {
        cwd: root,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'inherit'],
      }),
    )
    syncSnapshot(join(root, 'packages/interfold-contracts/crypto-config.json'), metadata, args[0] === '--check')
  } catch (error) {
    console.error(error.message)
    process.exitCode = error.status || 1
  }
}
