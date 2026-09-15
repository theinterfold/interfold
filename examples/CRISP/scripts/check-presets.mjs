#!/usr/bin/env node
// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Refuse to publish a channel whose artifacts do not match the presets that channel stands for.
//
// The testing channel carries only insecure so testnet installs stay small. The production
// channel carries every supported preset so one client can select the preset from the E3's
// on-chain param set.
//
// The SDK and the contracts package are checked together because they are a matched pair. The SDK
// inlines the compiled circuit and the contracts package ships the verifier generated from that
// same circuit's verification key, so a channel that mixes them fails on chain at proof
// verification rather than anywhere a test would catch it.

import { existsSync, readFileSync, statSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const CRISP = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const SDK = join(CRISP, 'packages', 'crisp-sdk')
const CONTRACTS = join(CRISP, 'packages', 'crisp-contracts')

/** Which presets each release channel carries. */
const CHANNEL_PRESETS = {
  testing: ['insecure'],
  latest: ['insecure', 'secure-8192', 'secure-16384'],
}

const ALL_PRESETS = [...new Set(Object.values(CHANNEL_PRESETS).flat())]

/** Generated per census mode. Not preset-specific — see packages/crisp-contracts/scripts/verifiers.ts. */
const VERIFIERS = ['CRISPVerifier.sol', 'CRISPOnchainVerifier.sol']

/** Polynomial degree each preset's circuits carry, used to prove the bundle is what it claims. */
const EXPECTED_DEGREE = { insecure: 512, 'secure-8192': 8192, 'secure-16384': 16384 }

/** Below this a "built" entry is a stub or a failed inline rather than a real circuit bundle. */
const MIN_BYTES = 100 * 1024

/** Above this an off-channel entry is probably a real circuit bundle rather than a resolver stub. */
const MAX_STUB_BYTES = 10 * 1024

// The bundler may emit the inlined JSON as a JS object literal, so the key can be quoted or bare
// and the space is optional. Match all of those rather than one spelling.
const hasDegree = (source, value) => new RegExp(`["']?length["']?\\s*:\\s*${value}\\b`).test(source)

// npm gives `prepublishOnly` no way to see `--tag`, so the channel comes through the environment
// when the publish scripts set it, and through argv when run by hand.
const channel = process.argv[2] ?? process.env.CRISP_CHANNEL
if (!channel || !Object.hasOwn(CHANNEL_PRESETS, channel)) {
  console.error(
    channel === undefined
      ? `Set CRISP_CHANNEL or pass a channel: check-presets.mjs <${Object.keys(CHANNEL_PRESETS).join('|')}>`
      : `Unknown channel "${channel}"; expected one of ${Object.keys(CHANNEL_PRESETS).join(', ')}.`,
  )
  process.exit(1)
}

const wanted = CHANNEL_PRESETS[channel]
const others = ALL_PRESETS.filter((preset) => !wanted.includes(preset))
const problems = []

// --- the SDK bundle ---
const built = new Map()
for (const preset of wanted) {
  const path = join(SDK, 'dist', 'presets', `${preset}.js`)
  built.set(preset, path)
  if (!existsSync(path)) {
    problems.push(`${preset}: dist/presets/${preset}.js is missing — run \`pnpm build:presets\`, then rebuild the SDK.`)
  } else if (statSync(path).size < MIN_BYTES) {
    problems.push(`${preset}: dist/presets/${preset}.js is only ${statSync(path).size} bytes; the circuits did not inline.`)
  }
}

// The exports map is what consumers actually resolve, so check it points at a real file.
const pkg = JSON.parse(readFileSync(join(SDK, 'package.json'), 'utf8'))
for (const preset of wanted) {
  const entry = pkg.exports?.[`./${preset}`]
  if (!entry) {
    problems.push(`${preset}: package.json exports has no "./${preset}" subpath.`)
  } else {
    for (const target of new Set(Object.values(entry))) {
      if (!existsSync(join(SDK, target))) problems.push(`${preset}: exports points at ${target}, which does not exist.`)
    }
  }
}

for (const other of others) {
  const path = join(SDK, 'dist', 'presets', `${other}.js`)
  if (!existsSync(path)) continue

  const source = readFileSync(path, 'utf8')
  const size = statSync(path).size
  const containsKnownDegree = Object.values(EXPECTED_DEGREE).some((degree) => hasDegree(source, degree))

  if (size > MAX_STUB_BYTES || containsKnownDegree) {
    problems.push(`${other}: "${channel}" may ship only a resolver stub for off-channel presets, not a real circuit bundle.`)
  }
}

// --- the bundle really carries the channel's circuits ---
//
// The filename says which preset a bundle is; this checks the contents agree. A bundle built from
// the wrong staged artifacts would ship under the right name and fail only at on-chain
// verification, which is the whole failure mode these channels exist to prevent.
for (const preset of wanted) {
  const path = built.get(preset)
  if (!existsSync(path)) continue

  const source = readFileSync(path, 'utf8')
  const degree = EXPECTED_DEGREE[preset]
  const unexpected = Object.entries(EXPECTED_DEGREE).filter(([candidate]) => candidate !== preset)

  if (!hasDegree(source, degree)) {
    problems.push(`${preset}: dist/presets/${preset}.js contains no length-${degree} arrays; the inlined circuits are not ${preset}.`)
  }
  for (const [otherPreset, otherDegree] of unexpected) {
    if (hasDegree(source, otherDegree)) {
      problems.push(`${preset}: dist/presets/${preset}.js contains length-${otherDegree} arrays, which belong to ${otherPreset}.`)
    }
  }
}

// --- the generated verifiers ---
//
// Preset-independent, so this is only an existence check: without them a consumer has nothing to
// deploy, but there is no wrong-preset case to catch here.
for (const verifier of VERIFIERS) {
  if (!existsSync(join(CONTRACTS, 'contracts', 'verifiers', verifier))) {
    problems.push(`contracts/verifiers/${verifier} is missing — regenerate with scripts/compile_circuits.sh.`)
  }
}

if (problems.length > 0) {
  console.error(`✗ Not publishable on "${channel}" (expects ${wanted.join(', ')}):`)
  for (const problem of problems) console.error(`  - ${problem}`)
  process.exit(1)
}

const sizes = wanted.map((preset) => `${preset} ${(statSync(built.get(preset)).size / 1048576).toFixed(1)}MB`).join(', ')
console.log(`✓ "${channel}" carries ${wanted.join(', ')} (${sizes}; verifiers present).`)
