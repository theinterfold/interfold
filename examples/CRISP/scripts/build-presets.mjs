#!/usr/bin/env node
// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Compile and stage the CRISP circuits for the requested preset set.
//
// The preset is a global compile-time choice (circuits/lib/src/configs/default/mod.nr), so the
// presets cannot be built concurrently — each pass switches the tree, compiles, and archives the
// result under circuits/dist/<preset>/ before the next pass overwrites it.
//
// The threshold circuits go through the root builder rather than a bare `nargo compile`, because
// switching preset also regenerates the parity matrices and ActiveCryptoConfig.sol. The root
// builder does not know about the CRISP circuits, so those are compiled here afterwards.

import { execFileSync } from 'node:child_process'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const CRISP = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const REPO = resolve(CRISP, '..', '..')
const ALL_PRESETS = ['secure-8192', 'secure-16384', 'insecure']

const usage = () => {
  console.error('Usage: build-presets.mjs [--preset insecure|secure-8192|secure-16384] [--all]')
  console.error('Defaults to --preset insecure for pull-request CI and local development.')
}

const args = process.argv.slice(2)
let requested = 'insecure'
for (let i = 0; i < args.length; i++) {
  const arg = args[i]
  if (arg === '--all') {
    requested = 'all'
  } else if (arg === '--preset') {
    requested = args[++i]
  } else {
    usage()
    process.exit(1)
  }
}

const PRESETS = requested === 'all' ? ALL_PRESETS : [requested]
for (const preset of PRESETS) {
  if (!ALL_PRESETS.includes(preset)) {
    usage()
    process.exit(1)
  }
}

const run = (cmd, args, cwd) => {
  console.log(`   $ ${cmd} ${args.join(' ')}`)
  execFileSync(cmd, args, { cwd, stdio: 'inherit' })
}

for (const preset of PRESETS) {
  console.log(`\n🔮 Building CRISP circuits for ${preset}...`)

  // Switches the tree to this preset. This is the step that also regenerates the parity matrices
  // and ActiveCryptoConfig.sol, which a bare `nargo compile` would leave describing the old one.
  run('pnpm', ['tsx', 'scripts/build-circuits.ts', '--preset', preset, '--group', 'threshold'], REPO)

  // Compiles the CRISP circuits and writes the generated Solidity verifiers into
  // packages/crisp-contracts/contracts/verifiers/<preset>/. It recompiles the threshold circuits on
  // the way through, which duplicates part of the step above; that is worth the few minutes rather
  // than splitting the verifier generation away from the compile it has to agree with.
  run('bash', ['scripts/compile_circuits.sh'], CRISP)

  run('node', [join(CRISP, 'scripts/stage-preset-artifacts.mjs'), preset], CRISP)
}

console.log(`\n✓ staged ${PRESETS.length} preset(s); tree left on ${PRESETS.at(-1)}`)
console.log('  If the ballot circuits changed, regenerate the fold key hashes: scripts/compute_vk_hash.sh')
if (requested === 'all') {
  console.log('  Then rebuild the production SDK: pnpm -C packages/crisp-sdk build:prod')
  console.log('  Then check it: CRISP_CHANNEL=latest pnpm -C packages/crisp-sdk check:presets')
} else {
  console.log('  Then rebuild the testing SDK: pnpm -C packages/crisp-sdk build')
}
