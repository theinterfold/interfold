// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import assert from 'node:assert/strict'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import {
  CIRCUIT_GROUPS,
  CIRCUIT_PRESETS,
  NoirCircuitBuilder,
  configModuleFiles,
  generatedConfigDrift,
  requiredRlkBinMarkers,
  requiredRlkDistMarkers,
  syncGeneratedConfigModules,
} from './build-circuits'

function writeFiles(files: string[]): void {
  for (const file of files) {
    mkdirSync(join(file, '..'), { recursive: true })
    writeFileSync(file, file)
  }
}

test('synchronizes and verifies nested l-BFV config modules', () => {
  const root = mkdtempSync(join(tmpdir(), 'interfold-config-sync-'))
  const generated = join(root, 'generated')
  const committed = join(root, 'committed')
  const modules = ['mod.nr', 'threshold.nr', 'dkg.nr', 'lbfv/mod.nr', 'lbfv/crs.nr', 'lbfv/urs.nr']

  try {
    writeFiles(modules.map((file) => join(generated, file)))
    writeFiles([join(committed, 'stale.nr')])
    syncGeneratedConfigModules(generated, committed)

    assert.deepEqual(configModuleFiles(committed), modules.toSorted())
    assert.equal(generatedConfigDrift(generated, committed), null)
    assert.equal(existsSync(join(committed, 'stale.nr')), false)

    writeFileSync(join(committed, 'lbfv', 'crs.nr'), 'stale CRS')
    assert.equal(generatedConfigDrift(generated, committed), 'lbfv/crs.nr')
    unlinkSync(join(committed, 'lbfv', 'urs.nr'))
    assert.equal(generatedConfigDrift(generated, committed), 'file set')
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('requires complete RLK artifacts only for secure-16384', () => {
  const root = '/artifacts'
  assert.equal(requiredRlkDistMarkers(root, CIRCUIT_PRESETS.SECURE_16384).length, 18)
  assert.equal(requiredRlkBinMarkers(root, CIRCUIT_PRESETS.SECURE_16384).length, 14)
  assert.deepEqual(requiredRlkDistMarkers(root, CIRCUIT_PRESETS.SECURE_8192), [])
  assert.deepEqual(requiredRlkBinMarkers(root, CIRCUIT_PRESETS.INSECURE_512), [])
})

function hydrationFixture(): {
  root: string
  outputDir: string
  hydrate: () => void
} {
  const root = mkdtempSync(join(tmpdir(), 'interfold-rlk-hydration-'))
  const bin = join(root, 'circuits', 'bin')
  const outputDir = join(root, 'dist', 'circuits')
  const pairDir = join(outputDir, CIRCUIT_PRESETS.SECURE_16384, 'minimum')

  for (const circuit of ['rlk_generation', 'rlk_aggregation']) {
    const circuitDir = join(bin, CIRCUIT_GROUPS.THRESHOLD, circuit)
    mkdirSync(circuitDir, { recursive: true })
    writeFileSync(join(circuitDir, 'Nargo.toml'), `[package]\nname = "${circuit}"\ntype = "bin"\n`)
    const targetDir = join(circuitDir, 'target')
    mkdirSync(targetDir, { recursive: true })
    writeFileSync(join(targetDir, `${circuit}.obsolete`), 'stale')
  }

  writeFiles([
    join(pairDir, 'default', CIRCUIT_GROUPS.DKG, 'pk', 'pk.json'),
    join(pairDir, 'default', CIRCUIT_GROUPS.THRESHOLD, 'pk_aggregation', 'pk_aggregation.json'),
    join(pairDir, 'default', CIRCUIT_GROUPS.AGGREGATION, 'dkg_aggregator', 'dkg_aggregator.json'),
    join(pairDir, 'default', CIRCUIT_GROUPS.AGGREGATION, 'decryption_aggregator', 'decryption_aggregator.json'),
    ...requiredRlkDistMarkers(pairDir, CIRCUIT_PRESETS.SECURE_16384),
  ])

  const builder = new NoirCircuitBuilder(root, {
    groups: [CIRCUIT_GROUPS.THRESHOLD],
    outputDir,
    preset: CIRCUIT_PRESETS.SECURE_16384,
    committee: 'minimum',
  })
  const hydrate = () =>
    (
      builder as unknown as {
        hydrateBinFromDist(preset: typeof CIRCUIT_PRESETS.SECURE_16384, committee: 'minimum', sourceHash: string): void
      }
    ).hydrateBinFromDist(CIRCUIT_PRESETS.SECURE_16384, 'minimum', 'source-hash')

  return { root, outputDir, hydrate }
}

test('hydrates all RLK targets and removes stale target artifacts', () => {
  const fixture = hydrationFixture()
  try {
    fixture.hydrate()
    for (const marker of requiredRlkBinMarkers(join(fixture.root, 'circuits', 'bin'), CIRCUIT_PRESETS.SECURE_16384)) {
      assert.equal(existsSync(marker), true)
    }
    assert.equal(
      existsSync(join(fixture.root, 'circuits', 'bin', 'threshold', 'rlk_generation', 'target', 'rlk_generation.obsolete')),
      false,
    )
    assert.equal(JSON.parse(readFileSync(join(fixture.root, 'circuits', 'bin', '.active-preset.json'), 'utf8')).sourceHash, 'source-hash')
  } finally {
    rmSync(fixture.root, { recursive: true, force: true })
  }
})

test('rejects RLK hydration before writing a stamp when an artifact is missing', () => {
  const fixture = hydrationFixture()
  try {
    const missing = requiredRlkDistMarkers(
      join(fixture.outputDir, CIRCUIT_PRESETS.SECURE_16384, 'minimum'),
      CIRCUIT_PRESETS.SECURE_16384,
    )[0]
    unlinkSync(missing)

    assert.throws(fixture.hydrate, /Cannot hydrate circuits\/bin: missing artifact/)
    assert.equal(existsSync(join(fixture.root, 'circuits', 'bin', '.active-preset.json')), false)
  } finally {
    rmSync(fixture.root, { recursive: true, force: true })
  }
})
