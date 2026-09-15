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
// time. The SDK needs both side by side to publish both, so each compile pass is archived here.
//
// Only the four circuits whose ABI is shaped by the BFV degree are staged. The aggregation
// circuits are proof-shaped and preset-independent — see src/circuits.ts.

import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { circuitSourcesDigest } from './circuit-sources.mjs'

const CRISP = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const REPO = resolve(CRISP, '..', '..')

/** Degree the preset's polynomials carry, used to prove the artifact matches its directory. */
const EXPECTED_DEGREE = { insecure: 512, 'secure-8192': 8192, 'secure-16384': 16384 }

const ARTIFACTS = [
  { name: 'crisp', from: join(CRISP, 'circuits/bin/crisp/target/crisp.json') },
  { name: 'crisp_onchain', from: join(CRISP, 'circuits/bin/crisp_onchain/target/crisp_onchain.json') },
  { name: 'user_data_encryption_ct0', from: join(REPO, 'circuits/bin/threshold/target/user_data_encryption_ct0.json') },
  { name: 'user_data_encryption_ct1', from: join(REPO, 'circuits/bin/threshold/target/user_data_encryption_ct1.json') },
]

/**
 * The largest array length in the ABI is the polynomial degree for every circuit staged here.
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

  // A circuit compiled at 512 carries 1023-length arrays too (the ct0/ct1 witnesses), so compare
  // against the maximum rather than looking the degree up by name.
  const degree = degreeOf(from)
  const expected = EXPECTED_DEGREE[preset]
  if (degree !== expected && degree !== 2 * expected - 1) {
    console.error(`✗ ${name}: ABI reports degree ${degree}, which is not ${preset}. Wrong preset compiled?`)
    process.exit(1)
  }

  copyFileSync(from, join(outDir, `${name}.json`))
  staged.push({ name, degree })
}

// The digest of the sources these artifacts were compiled from. check-staged-preset.mjs
// recomputes it, so a later channel build cannot use an archive the circuits have moved past.
const { digest, fileCount } = circuitSourcesDigest()

const manifest = { preset, circuits: staged.map((s) => s.name), sources: { digest, fileCount } }
writeFileSync(join(outDir, 'preset.json'), `${JSON.stringify(manifest, null, 2)}\n`)
console.log(`✓ staged ${staged.length} artifact(s) for ${preset}: ${staged.map((s) => s.name).join(', ')}`)
