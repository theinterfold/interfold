// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { NoirCircuitBuilder, normalizeCargoLockForCircuitHash } from './build-circuits'
import {
  copyArtifactsInto,
  findArtifactRevision,
  RELEASE_REQUIRED_PAIRS,
  requiredArtifactMarkers,
  validateArtifactSet,
  validateReleaseArtifacts,
} from './circuit-artifacts'

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

test('publishing copies only supported preset and committee pairs', () => {
  const source = makeCompleteMatrix()
  const target = mkdtempSync(join(tmpdir(), 'interfold-circuit-publish-'))
  try {
    const legacy = join(source, 'insecure', 'micro')
    mkdirSync(legacy, { recursive: true })
    writeFileSync(join(legacy, '.build-stamp.json'), '{}')

    copyArtifactsInto(target, source)
    assert.equal(existsSync(join(target, 'insecure')), false)
    validateArtifactSet(target, sourceHash)
  } finally {
    rmSync(source, { recursive: true, force: true })
    rmSync(target, { recursive: true, force: true })
  }
})

test('artifact selection uses the newest matching build, not another source tree at the branch tip', () => {
  const dir = mkdtempSync(join(tmpdir(), 'interfold-circuit-history-'))
  const git = (...args: string[]) => execFileSync('git', args, { cwd: dir, encoding: 'utf8' }).trim()
  const commit = (message: string) => {
    git('add', '.')
    git(
      '-c',
      'user.name=Circuit Test',
      '-c',
      'user.email=circuit-test@example.invalid',
      '-c',
      'commit.gpgsign=false',
      'commit',
      '-qm',
      message,
    )
    return git('rev-parse', 'HEAD')
  }

  try {
    git('init', '-q')
    writeFileSync(join(dir, 'artifact.json'), '{}')
    commit('legacy build without source metadata')
    assert.throws(() => findArtifactRevision(dir, 'HEAD', 'requested-source'), /No published circuit artifacts match/)

    writeFileSync(join(dir, 'SOURCE_HASH'), 'requested-source\n')
    commit('requested build')
    writeFileSync(join(dir, 'artifact.json'), '{"rebuilt":true}')
    const rebuilt = commit('same source with updated artifacts')
    assert.equal(findArtifactRevision(dir, 'HEAD', 'requested-source'), rebuilt)

    writeFileSync(join(dir, 'SOURCE_HASH'), 'other-source\n')
    const newer = commit('build for another source tree')
    assert.equal(findArtifactRevision(dir, 'HEAD', 'requested-source'), rebuilt)
    assert.equal(findArtifactRevision(dir, 'HEAD', 'other-source'), newer)
    assert.throws(() => findArtifactRevision(dir, 'HEAD', 'unpublished-source'), /No published circuit artifacts match/)
    assert.equal(git('rev-parse', 'HEAD'), newer)
    assert.equal(git('status', '--porcelain'), '')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('circuit hash tracks external crate pins and ignores the workspace graph', () => {
  const external = `[[package]]\nname = "external"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "1111"\n`
  const member = `[[package]]\nname = "e3-example"\nversion = "0.14.0"\ndependencies = [\n "e3-test-helpers",\n "external",\n]\n`
  const before = Buffer.from(`[version]\n3\n\n${member}\n${external}`)
  const edited = (from: string, to: string) => Buffer.from(before.toString().replace(from, to))

  // A release bump and an internal dependency edit leave every circuit input untouched.
  assert.deepEqual(
    normalizeCargoLockForCircuitHash(edited('version = "0.14.0"', 'version = "0.15.0"')),
    normalizeCargoLockForCircuitHash(before),
  )
  assert.deepEqual(normalizeCargoLockForCircuitHash(edited(' "e3-test-helpers",\n', '')), normalizeCargoLockForCircuitHash(before))

  // A different external crate can compile the generators into different bounds.
  assert.notDeepEqual(
    normalizeCargoLockForCircuitHash(edited('version = "1.0.0"', 'version = "1.0.1"')),
    normalizeCargoLockForCircuitHash(before),
  )
  assert.notDeepEqual(
    normalizeCargoLockForCircuitHash(edited('checksum = "1111"', 'checksum = "2222"')),
    normalizeCargoLockForCircuitHash(before),
  )
})

test('pair source hash ignores generated bounds but tracks other Noir config', () => {
  const dir = mkdtempSync(join(tmpdir(), 'interfold-circuit-hash-'))
  const configDir = join(dir, 'circuits', 'lib', 'src', 'configs', 'insecure')
  mkdirSync(configDir, { recursive: true })
  const thresholdPath = join(configDir, 'threshold.nr')
  const dkgPath = join(configDir, 'dkg.nr')
  writeFileSync(
    thresholdPath,
    'pub global PK_GENERATION_E_SM_BOUND: Field = 10;\npub global PK_GENERATION_R2_BOUNDS: [Field; L] =\n    [11, 12];\npub global L: u32 = 2;\n',
  )
  writeFileSync(dkgPath, 'pub global SHARE_COMPUTATION_E_SM_BIT_SECRET: u32 = 28;\n')

  try {
    const builder = new NoirCircuitBuilder(dir, { preset: 'insecure-512', committee: 'micro' })
    const originalHash = builder.computeSourceHash('insecure-512', 'micro')
    writeFileSync(
      thresholdPath,
      'pub global PK_GENERATION_E_SM_BOUND: Field = 20;\npub global PK_GENERATION_R2_BOUNDS: [Field; L] = [21, 22];\npub global L: u32 = 2;\n',
    )
    writeFileSync(dkgPath, 'pub global SHARE_COMPUTATION_E_SM_BIT_SECRET: u32 = 30;\n')
    assert.equal(builder.computeSourceHash('insecure-512', 'micro'), originalHash)

    writeFileSync(
      thresholdPath,
      'pub global PK_GENERATION_E_SM_BOUND: Field = 20;\npub global PK_GENERATION_R2_BOUNDS: [Field; L] = [21, 22];\npub global L: u32 = 3;\n',
    )
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
