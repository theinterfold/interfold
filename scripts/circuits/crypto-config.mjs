// SPDX-License-Identifier: LGPL-3.0-only

import { execFileSync } from 'node:child_process'
import { readFileSync, realpathSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
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
    const artifactIndex = args.indexOf('--artifacts-dir')
    const artifactDir = artifactIndex === -1 ? undefined : args[artifactIndex + 1]
    if (artifactIndex !== -1 && (!artifactDir || artifactDir.startsWith('--'))) throw new Error('--artifacts-dir requires a directory')
    const flags = artifactIndex === -1 ? args : args.filter((_, index) => index !== artifactIndex && index !== artifactIndex + 1)
    if (flags.some((arg) => !['--check', '--sources', '--full', '--bindings-only', '--qualify'].includes(arg)))
      throw new Error('Usage: crypto-config.mjs [--check] [--sources | --full | --bindings-only] [--qualify] [--artifacts-dir path]')
    const root = fileURLToPath(new URL('../..', import.meta.url))
    const metadata = JSON.parse(
      execFileSync('cargo', ['run', '--quiet', '--locked', '-p', 'e3-zk-build', '--', 'export-config'], {
        cwd: root,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'inherit'],
      }),
    )
    const check = flags.includes('--check')
    const full = flags.includes('--full') && !flags.includes('--bindings-only')
    const sources = full || flags.includes('--sources') || flags.includes('--bindings-only')
    const qualify = flags.includes('--qualify')
    if (full && !check) throw new Error('Full mode is check-only; prepare artifacts explicitly')
    if (qualify && !full) throw new Error('--qualify requires --check --full')
    if (artifactDir && !full) throw new Error('--artifacts-dir requires --check --full')
    if (check && sources) {
      // This existing gate already invokes the Rust generated-source and ownership checks.
      // Its standalone fallback is lightweight; the aggregate source check must not skip Noir.
      execFileSync('nargo', ['--version'], { cwd: root, stdio: 'ignore' })
      execFileSync('/bin/bash', ['scripts/checks/committee.sh'], { cwd: root, stdio: 'inherit' })
    } else {
      execFileSync('cargo', ['run', '--quiet', '--locked', '-p', 'e3-zk-build', '--', check ? 'check-bindings' : 'sync-bindings'], {
        cwd: root,
        stdio: 'inherit',
      })
    }
    syncSnapshot(join(root, 'packages/interfold-contracts/crypto-config.json'), metadata, check)
    if (sources) {
      if (!check)
        execFileSync('cargo', ['run', '--quiet', '--locked', '-p', 'e3-zk-build', '--', 'sync-sources', '--committee', 'all'], {
          cwd: root,
          stdio: 'inherit',
        })
      console.log('Checked complete generated sources and registered consumer ownership. This is source-only, not artifact acceptance.')
    }
    if (full) {
      const directory = artifactDir ? resolve(artifactDir) : join(root, 'dist/circuits')
      execFileSync(
        'pnpm',
        [
          'exec',
          'tsx',
          '-e',
          'const a=require(process.argv[1]); a.validateArtifactSet(process.argv[2]); a.validateChecksums(process.argv[2]);',
          join(root, 'scripts/circuits/artifacts.ts'),
          directory,
        ],
        { cwd: root, stdio: 'inherit' },
      )
      for (const operation of ['check-identities', 'check-layouts', ...(qualify ? ['qualify-identities'] : [])]) {
        execFileSync(
          'cargo',
          [
            'run',
            '--quiet',
            '--locked',
            '-p',
            'e3-zk-build',
            '--',
            operation,
            '--preset',
            'all',
            '--committee',
            'all',
            '--output',
            directory,
          ],
          { cwd: root, stdio: 'inherit' },
        )
      }
      console.log(
        qualify
          ? 'Qualified the prepared matrix with independent VK and Solidity verifier rederivation.'
          : 'Checked prepared source stamps, artifact inventory/checksums, named identities, and compiled layouts. Backend keys were not rederived.',
      )
    }
  } catch (error) {
    console.error(error.message)
    process.exitCode = error.status || 1
  }
}
