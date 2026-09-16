// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { NoirCircuitBuilder } from './build-circuits'
import { RELEASE_REQUIRED_PAIRS, requiredArtifactMarkers, validateArtifactSet, validateReleaseArtifacts } from './circuit-artifacts'

function sourceHash(preset: string, committee: string): string {
  return `source:${preset}:${committee}`
}

function makeCompleteMatrix(): string {
  const dir = mkdtempSync(join(tmpdir(), 'interfold-circuit-matrix-'))
  for (const [preset, committee] of RELEASE_REQUIRED_PAIRS) {
    const pairDir = join(dir, preset, committee)
    mkdirSync(pairDir, { recursive: true })
    writeFileSync(join(pairDir, '.build-stamp.json'), JSON.stringify({ preset, committee, sourceHash: sourceHash(preset, committee) }))
    for (const marker of requiredArtifactMarkers(preset, committee)) {
      const markerPath = join(dir, marker)
      mkdirSync(join(markerPath, '..'), { recursive: true })
      writeFileSync(markerPath, '{}')
    }
  }
  return dir
}

test('pair source hash ignores generated bounds but tracks other Noir config', () => {
  const dir = mkdtempSync(join(tmpdir(), 'interfold-circuit-hash-'))
  const configDir = join(dir, 'circuits', 'lib', 'src', 'configs', 'insecure')
  mkdirSync(configDir, { recursive: true })
  const thresholdPath = join(configDir, 'threshold.nr')
  const dkgPath = join(configDir, 'dkg.nr')
  writeFileSync(thresholdPath, 'pub global PK_GENERATION_E_SM_BOUND: Field = 10;\npub global L: u32 = 2;\n')
  writeFileSync(dkgPath, 'pub global SHARE_COMPUTATION_E_SM_BIT_SECRET: u32 = 28;\n')

  try {
    const builder = new NoirCircuitBuilder(dir, { preset: 'insecure-512', committee: 'micro' })
    const originalHash = builder.computeSourceHash('insecure-512', 'micro')
    writeFileSync(thresholdPath, 'pub global PK_GENERATION_E_SM_BOUND: Field = 20;\npub global L: u32 = 2;\n')
    writeFileSync(dkgPath, 'pub global SHARE_COMPUTATION_E_SM_BIT_SECRET: u32 = 30;\n')
    assert.equal(builder.computeSourceHash('insecure-512', 'micro'), originalHash)

    writeFileSync(thresholdPath, 'pub global PK_GENERATION_E_SM_BOUND: Field = 20;\npub global L: u32 = 3;\n')
    assert.notEqual(builder.computeSourceHash('insecure-512', 'micro'), originalHash)

    const generatorDir = join(dir, 'crates', 'zk-helpers', 'src')
    mkdirSync(generatorDir, { recursive: true })
    const generatorPath = join(generatorDir, 'generator.rs')
    writeFileSync(generatorPath, 'first')
    const generatorHash = builder.computeSourceHash('insecure-512', 'micro')
    writeFileSync(generatorPath, 'second')
    assert.notEqual(builder.computeSourceHash('insecure-512', 'micro'), generatorHash)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('hydrate replaces stale targets at the paths used by Nargo', () => {
  const dir = mkdtempSync(join(tmpdir(), 'interfold-circuit-hydrate-'))
  const outputDir = join(dir, 'dist', 'circuits')
  const preset = 'insecure-512'
  const committee = 'small'
  const source = 'source-hash'

  const fixtures = [
    {
      group: 'dkg',
      name: 'sk_share_computation',
      workspace: true,
      expectedTarget: join(dir, 'circuits', 'bin', 'dkg', 'target'),
    },
    {
      group: 'recursive_aggregation',
      name: 'c3_fold',
      workspace: false,
      expectedTarget: join(dir, 'circuits', 'bin', 'recursive_aggregation', 'c3_fold', 'target'),
    },
  ] as const

  try {
    for (const fixture of fixtures) {
      const groupDir = join(dir, 'circuits', 'bin', fixture.group)
      const circuitDir = join(groupDir, fixture.name)
      mkdirSync(circuitDir, { recursive: true })
      if (fixture.workspace) {
        writeFileSync(join(groupDir, 'Nargo.toml'), `[workspace]\nmembers = ["${fixture.name}"]\n`)
      }
      writeFileSync(join(circuitDir, 'Nargo.toml'), `[package]\nname = "${fixture.name}"\ntype = "bin"\n`)

      mkdirSync(fixture.expectedTarget, { recursive: true })
      writeFileSync(join(fixture.expectedTarget, `${fixture.name}.json`), 'stale')

      const pairRoot = join(outputDir, preset, committee)
      for (const variant of ['default', 'evm', 'recursive']) {
        const artifactDir = join(pairRoot, variant, fixture.group, fixture.name)
        mkdirSync(artifactDir, { recursive: true })
        if (variant === 'default') {
          writeFileSync(join(artifactDir, `${fixture.name}.json`), `${fixture.name}-fresh`)
        }
        writeFileSync(join(artifactDir, `${fixture.name}.vk`), `${variant}-vk`)
        writeFileSync(join(artifactDir, `${fixture.name}.vk_hash`), `${variant}-hash`)
      }
    }

    const builder = new NoirCircuitBuilder(dir, { outputDir, preset, committee })
    const hydrate = builder as unknown as {
      hydrateBinFromDist: (selectedPreset: 'insecure-512', selectedCommittee: 'small', hash: string) => void
    }
    hydrate.hydrateBinFromDist(preset, committee, source)

    for (const fixture of fixtures) {
      assert.equal(readFileSync(join(fixture.expectedTarget, `${fixture.name}.json`), 'utf8'), `${fixture.name}-fresh`)
      assert.equal(readFileSync(join(fixture.expectedTarget, `${fixture.name}.vk_recursive`), 'utf8'), 'default-vk')
      assert.equal(readFileSync(join(fixture.expectedTarget, `${fixture.name}.vk`), 'utf8'), 'evm-vk')
      assert.equal(readFileSync(join(fixture.expectedTarget, `${fixture.name}.vk_noir`), 'utf8'), 'recursive-vk')
    }

    const stamp = JSON.parse(readFileSync(join(dir, 'circuits', 'bin', '.active-preset.json'), 'utf8'))
    assert.deepEqual(
      { preset: stamp.preset, committee: stamp.committee, sourceHash: stamp.sourceHash },
      { preset, committee, sourceHash: source },
    )
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('accepts the exact supported circuit matrix', () => {
  const dir = makeCompleteMatrix()
  try {
    assert.doesNotThrow(() => validateReleaseArtifacts(dir, sourceHash))
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('rejects a pair whose build stamp is missing', () => {
  const dir = makeCompleteMatrix()
  try {
    unlinkSync(join(dir, 'secure-8192', 'small', '.build-stamp.json'))
    assert.throws(() => validateReleaseArtifacts(dir, sourceHash), /Missing circuit build stamp/)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('rejects a build stamp that declares a different pair', () => {
  const dir = makeCompleteMatrix()
  try {
    writeFileSync(
      join(dir, 'secure-8192', 'small', '.build-stamp.json'),
      JSON.stringify({ preset: 'insecure-512', committee: 'small', sourceHash: sourceHash('secure-8192', 'small') }),
    )
    assert.throws(() => validateReleaseArtifacts(dir, sourceHash), /Invalid circuit build stamp/)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('rejects a pair whose build stamp has a stale source hash', () => {
  const dir = makeCompleteMatrix()
  try {
    writeFileSync(
      join(dir, 'secure-8192', 'small', '.build-stamp.json'),
      JSON.stringify({ preset: 'secure-8192', committee: 'small', sourceHash: 'stale-source' }),
    )
    assert.throws(() => validateReleaseArtifacts(dir, sourceHash), /Stale circuit artifacts/)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('rejects a stamp-valid pair with a missing verification-key artifact', () => {
  for (const extension of ['.vk', '.vk_hash']) {
    const dir = makeCompleteMatrix()
    try {
      const marker = requiredArtifactMarkers('secure-8192', 'small').find((artifact) => artifact.endsWith(extension))
      assert.ok(marker)
      unlinkSync(join(dir, marker))
      assert.throws(() => validateReleaseArtifacts(dir, sourceHash), /Incomplete circuit artifacts/)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  }
})

test('rejects an extra build stamp under a supported pair', () => {
  const dir = makeCompleteMatrix()
  try {
    const extraStamp = join(dir, 'secure-8192', 'small', 'stale', '.build-stamp.json')
    mkdirSync(join(extraStamp, '..'), { recursive: true })
    writeFileSync(extraStamp, JSON.stringify({ preset: 'secure-8192', committee: 'small', sourceHash: sourceHash('secure-8192', 'small') }))
    assert.throws(() => validateArtifactSet(dir, sourceHash), /Unexpected circuit build stamp/)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
