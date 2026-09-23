#!/usr/bin/env node
// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Stage the preset-bound circuit artifacts into circuits/dist/<preset>/.
//
// `nargo compile` always writes to <circuit>/target/, and the preset is chosen globally in
// circuits/lib/src/configs/default/mod.nr, so the working tree only ever holds one preset at a
// time. The SDK needs all presets side by side, so each compile pass is archived here.
//
// Stage each BFV-shaped ballot circuit and each circuit in the recursive encryption tree. The
// wrapper and fold circuits are proof-shaped and preset-independent. See src/circuits.ts.

import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { circuitSourcesDigest } from './circuit-sources.mjs'
import { PRESET_ARTIFACTS } from './preset-artifacts.mjs'

const CRISP = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const REPO = resolve(CRISP, '..', '..')

/** Degree the preset's polynomials carry, used to prove the artifact matches its directory. */
const EXPECTED_DEGREE = { insecure: 128, 'secure-8192': 8192, 'secure-16384': 16384 }

const ARTIFACTS = PRESET_ARTIFACTS.map((name) => ({
  name,
  from:
    name === 'crisp' || name === 'crisp_onchain'
      ? join(CRISP, 'circuits/bin', name, 'target', `${name}.json`)
      : join(REPO, 'circuits/bin/threshold/target', `${name}.json`),
}))

const DEGREE_SENTINELS = new Set(['crisp', 'crisp_onchain', 'ct0_pk_ct_commit', 'ct1_pk_ct_commit'])

/**
 * The sentinel circuits contain a complete degree-N polynomial in their ABI.
 *
 * Checking it is what stops a mislabelled archive. Staging an insecure artifact into secure-8192/
 * would otherwise publish a bundle that proves against the wrong parameters, and that failure only
 * surfaces on chain at verification time.
 */
const degreeOf = (path) => {
  const abi = JSON.parse(readFileSync(path, 'utf8')).abi
  const lengths = JSON.stringify(abi.parameters).match(/"length":(\d+)/g) ?? []

  return Math.max(...lengths.map((entry) => Number(entry.split(':')[1])), 0)
}

const preset = process.argv[2]
if (!Object.hasOwn(EXPECTED_DEGREE, preset)) {
  console.error(`Usage: stage-preset-artifacts.mjs <${Object.keys(EXPECTED_DEGREE).join('|')}>`)
  process.exit(1)
}

const outDir = join(CRISP, 'circuits/dist', preset)
mkdirSync(outDir, { recursive: true })

const staged = []
for (const { name, from } of ARTIFACTS) {
  if (!existsSync(from)) {
    console.error(`✗ ${name}: not compiled (${from})`)
    process.exit(1)
  }

  // Some recursive circuits contain only proof-shaped arrays. Check the circuits that contain a
  // complete polynomial, because they identify the preset for the complete staged set.
  const degree = degreeOf(from)
  const expected = EXPECTED_DEGREE[preset]
  if (DEGREE_SENTINELS.has(name) && degree !== expected && degree !== 2 * expected - 1) {
    console.error(`✗ ${name}: ABI reports degree ${degree}, which is not ${preset}. Wrong preset compiled?`)
    process.exit(1)
  }

  copyFileSync(from, join(outDir, `${name}.json`))
  staged.push({ name, degree })
}

// The digest of the sources these artifacts were compiled from. check-staged-preset.mjs
// recomputes it, so a later channel build cannot use an archive the circuits have moved past.
const { digest, fileCount } = circuitSourcesDigest()

const manifest = { preset, circuits: staged.map((s) => s.name), sources: { version: 2, digest, fileCount } }
writeFileSync(join(outDir, 'preset.json'), `${JSON.stringify(manifest, null, 2)}\n`)
console.log(`✓ staged ${staged.length} artifact(s) for ${preset}: ${staged.map((s) => s.name).join(', ')}`)
