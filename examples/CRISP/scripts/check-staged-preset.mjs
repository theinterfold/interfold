#!/usr/bin/env node
// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Refuse to build the SDK against staged artifacts that are missing or older than the circuits.
//
// `build:testing` and `build:prod` do not compile. They read what a previous `pnpm build:presets`
// left in circuits/dist/<preset>/, and git does not track that directory. A stale archive therefore
// builds without an error and ships circuits that no longer match the sources, and that failure
// only appears on chain at proof verification.
//
// The comparison is a content digest recorded at staging time, not a modification time, because a
// `git checkout` rewrites modification times for files whose content did not change.

import { existsSync, readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { circuitSourcesDigest } from './circuit-sources.mjs'

const CRISP = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const PRESETS = ['insecure', 'secure-8192', 'secure-16384']

const RESTAGE = 'Run `pnpm build:presets` for one preset, or `pnpm build:presets:all` for all presets, from examples/CRISP.'

const fail = (...lines) => {
  for (const line of lines) console.error(line)
  process.exit(1)
}

const preset = process.argv[2]
if (!PRESETS.includes(preset)) {
  fail(`Usage: check-staged-preset.mjs <${PRESETS.join('|')}>`)
}

const stagedDir = join(CRISP, 'circuits/dist', preset)
const manifestPath = join(stagedDir, 'preset.json')

if (!existsSync(manifestPath)) {
  fail(`✗ ${preset} is not staged (${stagedDir} has no preset.json).`, `  ${RESTAGE}`)
}

const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'))

if (manifest.preset !== preset) {
  fail(`✗ circuits/dist/${preset}/preset.json says it holds "${manifest.preset}".`, `  ${RESTAGE}`)
}

for (const name of manifest.circuits) {
  if (!existsSync(join(stagedDir, `${name}.json`))) {
    fail(`✗ ${preset}: preset.json lists ${name}, but ${name}.json is missing.`, `  ${RESTAGE}`)
  }
}

// An archive from before the digest existed cannot be shown to match, so treat it as stale.
if (!manifest.sources?.digest) {
  fail(`✗ ${preset} was staged before this check existed and carries no source digest.`, `  ${RESTAGE}`)
}

const { digest, fileCount } = circuitSourcesDigest()

if (digest !== manifest.sources.digest) {
  fail(
    `✗ ${preset} is staged from circuits that have changed since.`,
    `  staged from: ${manifest.sources.digest.slice(0, 12)} (${manifest.sources.fileCount} source files)`,
    `  tree now at: ${digest.slice(0, 12)} (${fileCount} source files)`,
    `  ${RESTAGE}`,
  )
}

console.log(`✓ ${preset} is staged from the current circuits (${fileCount} source files, ${digest.slice(0, 12)}).`)
