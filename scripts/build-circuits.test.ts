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
import { AbiCoder, id, keccak256 } from 'ethers'
import { BFV_PARAMS } from '../packages/interfold-contracts/scripts/protocol/constants'
import { CIRCUIT_COMMITTEES } from './circuit-constants'
import {
  CIRCUIT_GROUPS,
  CIRCUIT_PRESETS,
  CIRCUIT_VERSION_LABEL,
  NoirCircuitBuilder,
  configModuleFiles,
  generatedConfigDrift,
  hydratedCircuitTargetDir,
  requiredLbfvBinMarkers,
  requiredLbfvDistMarkers,
  syncGeneratedConfigModules,
} from './build-circuits'

test('the v2 circuit label changes the insecure configuration ID', () => {
  const abiCoder = AbiCoder.defaultAbiCoder()
  const params = BFV_PARAMS.insecure
  const encodedParams = abiCoder.encode(
    ['tuple(uint256 degree,uint256 plaintext_modulus,uint256[] moduli,string error1_variance)'],
    [[params.degree, params.plaintextModulus, [...params.moduli], params.error1Variance]],
  )
  const configId = (label: string) =>
    keccak256(abiCoder.encode(['bytes32', 'bytes32', 'bytes32'], [id('fhe.rs:BFV'), keccak256(encodedParams), id(label)]))

  assert.equal(CIRCUIT_VERSION_LABEL, 'interfold-bfv-v2')
  assert.equal(configId(CIRCUIT_VERSION_LABEL), '0x7317c190ccb1dccfa505bf5b9b923e341905f6675c16f958e0a7d853795517a5')
  assert.notEqual(configId(CIRCUIT_VERSION_LABEL), configId('interfold-bfv-v1'))
})

test('does not advertise unsupported secure-16384 committee pairs', () => {
  assert.doesNotThrow(
    () =>
      new NoirCircuitBuilder(undefined, {
        preset: CIRCUIT_PRESETS.SECURE_16384,
        committee: CIRCUIT_COMMITTEES.MINIMUM,
      }),
  )
  for (const committee of [CIRCUIT_COMMITTEES.MICRO, CIRCUIT_COMMITTEES.SMALL]) {
    assert.throws(
      () =>
        new NoirCircuitBuilder(undefined, {
          preset: CIRCUIT_PRESETS.SECURE_16384,
          committee,
        }),
      /Unsupported preset\/committee pair/,
    )
  }
})

test('partial circuit group builds do not claim complete preset stamps', () => {
  const complete = new NoirCircuitBuilder(undefined, {}) as unknown as {
    hasCompleteCircuitSelection: () => boolean
  }
  const thresholdOnly = new NoirCircuitBuilder(undefined, {
    groups: [CIRCUIT_GROUPS.THRESHOLD],
  }) as unknown as { hasCompleteCircuitSelection: () => boolean }

  assert.equal(complete.hasCompleteCircuitSelection(), true)
  assert.equal(thresholdOnly.hasCompleteCircuitSelection(), false)
})

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

test('requires complete l-BFV artifacts for supported presets', () => {
  const root = '/artifacts'
  assert.equal(requiredLbfvDistMarkers(root, CIRCUIT_PRESETS.INSECURE).length, 81)
  assert.equal(requiredLbfvBinMarkers(root, CIRCUIT_PRESETS.INSECURE).length, 68)
  assert.equal(requiredLbfvDistMarkers(root, CIRCUIT_PRESETS.SECURE_16384).length, 81)
  assert.equal(requiredLbfvBinMarkers(root, CIRCUIT_PRESETS.SECURE_16384).length, 68)
  assert.deepEqual(requiredLbfvDistMarkers(root, CIRCUIT_PRESETS.SECURE_8192), [])
  assert.deepEqual(requiredLbfvBinMarkers(root, CIRCUIT_PRESETS.SECURE_8192), [])
})

test('source hash covers compile-bearing Noir inputs but ignores active selectors', () => {
  const root = mkdtempSync(join(tmpdir(), 'interfold-source-hash-'))
  const sharedSource = join(root, 'circuits', 'lib', 'src', 'core', 'shared.nr')
  const sharedManifest = join(root, 'circuits', 'lib', 'Nargo.toml')
  const defaultConfig = join(root, 'circuits', 'lib', 'src', 'configs', 'default', 'mod.nr')
  const activeCommittee = join(root, 'circuits', 'lib', 'src', 'configs', 'committee', 'active.nr')
  const presetSource = join(root, 'circuits', 'lib', 'src', 'configs', 'insecure', 'threshold.nr')
  const committeeSource = join(root, 'circuits', 'lib', 'src', 'configs', 'committee', 'minimum', 'mod.nr')
  const microCommitteeSource = join(root, 'circuits', 'lib', 'src', 'configs', 'committee', 'micro', 'mod.nr')
  const smallCommitteeSource = join(root, 'circuits', 'lib', 'src', 'configs', 'committee', 'small', 'mod.nr')
  const workspaceManifest = join(root, 'circuits', 'bin', 'threshold', 'Nargo.toml')
  const thresholdSecureSource = join(root, 'circuits', 'bin', 'recursive_aggregation', 'node_fold_v2', 'src', 'main.nr')
  const aggregationSecureSource = join(root, 'circuits', 'bin', 'recursive_aggregation', 'dkg_aggregator_v2', 'src', 'main.nr')
  const defaultContent = (preset: string, maxCoefficients: number) =>
    [
      `// Auto-generated by build-circuits.ts for preset: ${preset}`,
      'pub use super::committee::active::{H, N_PARTIES, T};',
      `pub use super::${preset}::dkg;`,
      `pub use super::${preset}::threshold;`,
      `pub global MAX_MSG_NON_ZERO_COEFFS: u32 = ${maxCoefficients};`,
    ].join('\n')
  try {
    writeFiles([
      sharedSource,
      sharedManifest,
      join(root, 'circuits', 'lib', 'src', 'lib.nr'),
      join(root, 'circuits', 'lib', 'src', 'configs', 'mod.nr'),
      join(root, 'circuits', 'lib', 'src', 'configs', 'committee', 'mod.nr'),
      defaultConfig,
      activeCommittee,
      presetSource,
      committeeSource,
      microCommitteeSource,
      smallCommitteeSource,
      workspaceManifest,
      join(root, 'circuits', 'bin', 'threshold', 'example', 'Nargo.toml'),
      join(root, 'circuits', 'bin', 'threshold', 'example', 'src', 'main.nr'),
      join(root, 'circuits', 'bin', 'recursive_aggregation', 'node_fold_v2', 'Nargo.toml'),
      thresholdSecureSource,
      join(root, 'circuits', 'bin', 'recursive_aggregation', 'dkg_aggregator_v2', 'Nargo.toml'),
      aggregationSecureSource,
    ])
    writeFileSync(sharedSource, 'shared relation')
    writeFileSync(sharedManifest, 'shared manifest')
    writeFileSync(defaultConfig, defaultContent('insecure', 100))
    writeFileSync(activeCommittee, 'minimum selector')
    writeFileSync(presetSource, 'preset constants')
    writeFileSync(committeeSource, 'committee constants')
    writeFileSync(microCommitteeSource, 'micro committee constants')
    writeFileSync(smallCommitteeSource, 'small committee constants')
    writeFileSync(workspaceManifest, '[workspace]\nmembers = ["example"]')
    const groups = [CIRCUIT_GROUPS.THRESHOLD, CIRCUIT_GROUPS.AGGREGATION]
    const builder = new NoirCircuitBuilder(root, {
      groups,
      preset: CIRCUIT_PRESETS.INSECURE,
      committee: 'minimum',
    })
    const secureBuilder = new NoirCircuitBuilder(root, {
      groups,
      preset: CIRCUIT_PRESETS.SECURE_16384,
      committee: 'minimum',
    })

    const before = builder.computeSourceHash(CIRCUIT_PRESETS.INSECURE, 'minimum')
    writeFileSync(defaultConfig, defaultContent('secure_16384', 100))
    writeFileSync(activeCommittee, 'changed active committee')
    assert.equal(builder.computeSourceHash(CIRCUIT_PRESETS.INSECURE, 'minimum'), before)

    writeFileSync(defaultConfig, defaultContent('secure_16384', 101))
    assert.notEqual(builder.computeSourceHash(CIRCUIT_PRESETS.INSECURE, 'minimum'), before)
    writeFileSync(defaultConfig, defaultContent('secure_16384', 100))

    writeFileSync(sharedSource, 'changed shared relation')
    assert.notEqual(builder.computeSourceHash(CIRCUIT_PRESETS.INSECURE, 'minimum'), before)
    writeFileSync(sharedSource, 'shared relation')

    writeFileSync(sharedManifest, 'changed shared manifest')
    assert.notEqual(builder.computeSourceHash(CIRCUIT_PRESETS.INSECURE, 'minimum'), before)
    writeFileSync(sharedManifest, 'shared manifest')

    writeFileSync(workspaceManifest, '[workspace]\nmembers = []')
    assert.notEqual(builder.computeSourceHash(CIRCUIT_PRESETS.INSECURE, 'minimum'), before)
    writeFileSync(workspaceManifest, '[workspace]\nmembers = ["example"]')

    writeFileSync(presetSource, 'changed preset constants')
    assert.notEqual(builder.computeSourceHash(CIRCUIT_PRESETS.INSECURE, 'minimum'), before)
    writeFileSync(presetSource, 'preset constants')

    writeFileSync(committeeSource, 'changed committee constants')
    assert.notEqual(builder.computeSourceHash(CIRCUIT_PRESETS.INSECURE, 'minimum'), before)
    writeFileSync(committeeSource, 'committee constants')

    const secureBefore = secureBuilder.computeSourceHash(CIRCUIT_PRESETS.SECURE_16384, 'minimum')
    writeFileSync(thresholdSecureSource, 'changed secure threshold circuit')
    writeFileSync(aggregationSecureSource, 'changed secure aggregation circuit')
    assert.notEqual(builder.computeSourceHash(CIRCUIT_PRESETS.INSECURE, 'minimum'), before)
    assert.notEqual(secureBuilder.computeSourceHash(CIRCUIT_PRESETS.SECURE_16384, 'minimum'), secureBefore)

    const archiveBefore = builder.computeSourceHash()
    writeFileSync(microCommitteeSource, 'changed micro committee constants')
    assert.notEqual(builder.computeSourceHash(), archiveBefore)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
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

  const secureCircuits = [
    ...[
      'lbfv_pk_generation',
      'lbfv_pk_generation_limb',
      'lbfv_pk_aggregation',
      'rlk_generation',
      'rlk_generation_limb',
      'rlk_aggregation',
    ].map((circuit) => [CIRCUIT_GROUPS.THRESHOLD, circuit]),
    ...[
      'lbfv_generation_fold',
      'lbfv_generation_fold_kernel',
      'node_fold_v2',
      'nodes_fold_v2',
      'nodes_fold_v2_kernel',
      'lbfv_aggregation_fold',
      'lbfv_aggregation_fold_kernel',
      'dkg_aggregator_v2',
    ].map((circuit) => [CIRCUIT_GROUPS.AGGREGATION, circuit]),
  ]
  for (const [group, circuit] of secureCircuits) {
    const circuitDir = join(bin, group, circuit)
    mkdirSync(circuitDir, { recursive: true })
    writeFileSync(join(circuitDir, 'Nargo.toml'), `[package]\nname = "${circuit}"\ntype = "bin"\n`)
    const targetDir = hydratedCircuitTargetDir(bin, group as (typeof CIRCUIT_GROUPS)[keyof typeof CIRCUIT_GROUPS], circuit)
    mkdirSync(targetDir, { recursive: true })
    writeFileSync(join(targetDir, `${circuit}.obsolete`), 'stale')
  }
  const thresholdMembers = [
    'pk_aggregation',
    ...secureCircuits.filter(([group]) => group === CIRCUIT_GROUPS.THRESHOLD).map(([, circuit]) => circuit),
  ]
  mkdirSync(join(bin, CIRCUIT_GROUPS.THRESHOLD, 'pk_aggregation'), { recursive: true })
  writeFileSync(join(bin, CIRCUIT_GROUPS.THRESHOLD, 'pk_aggregation', 'Nargo.toml'), '[package]\nname = "pk_aggregation"\ntype = "bin"\n')
  writeFileSync(
    join(bin, CIRCUIT_GROUPS.THRESHOLD, 'Nargo.toml'),
    `[workspace]\nmembers = [${thresholdMembers.map((member) => `"${member}"`).join(', ')}]\n`,
  )

  writeFiles([
    join(pairDir, 'default', CIRCUIT_GROUPS.DKG, 'pk', 'pk.json'),
    join(pairDir, 'default', CIRCUIT_GROUPS.THRESHOLD, 'pk_aggregation', 'pk_aggregation.json'),
    join(pairDir, 'default', CIRCUIT_GROUPS.AGGREGATION, 'dkg_aggregator', 'dkg_aggregator.json'),
    join(pairDir, 'default', CIRCUIT_GROUPS.AGGREGATION, 'dkg_aggregator', 'dkg_aggregator.vk'),
    join(pairDir, 'default', CIRCUIT_GROUPS.AGGREGATION, 'decryption_aggregator', 'decryption_aggregator.json'),
    join(pairDir, 'default', CIRCUIT_GROUPS.AGGREGATION, 'decryption_aggregator', 'decryption_aggregator.vk'),
    ...requiredLbfvDistMarkers(pairDir, CIRCUIT_PRESETS.SECURE_16384),
    join(bin, CIRCUIT_GROUPS.DKG, 'target', 'pk.json'),
    join(bin, CIRCUIT_GROUPS.THRESHOLD, 'target', 'pk_aggregation.json'),
    join(bin, CIRCUIT_GROUPS.AGGREGATION, 'dkg_aggregator', 'target', 'dkg_aggregator.json'),
    join(bin, CIRCUIT_GROUPS.AGGREGATION, 'dkg_aggregator', 'target', 'dkg_aggregator.vk_recursive'),
    join(bin, CIRCUIT_GROUPS.AGGREGATION, 'decryption_aggregator', 'target', 'decryption_aggregator.json'),
    join(bin, CIRCUIT_GROUPS.AGGREGATION, 'decryption_aggregator', 'target', 'decryption_aggregator.vk_recursive'),
  ])

  const builder = new NoirCircuitBuilder(root, {
    groups: [CIRCUIT_GROUPS.THRESHOLD, CIRCUIT_GROUPS.AGGREGATION],
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

test('hydrates the complete l-BFV family and removes stale target artifacts', () => {
  const fixture = hydrationFixture()
  try {
    fixture.hydrate()
    for (const marker of requiredLbfvBinMarkers(join(fixture.root, 'circuits', 'bin'), CIRCUIT_PRESETS.SECURE_16384)) {
      assert.equal(existsSync(marker), true)
    }
    assert.equal(existsSync(join(fixture.root, 'circuits', 'bin', 'threshold', 'target', 'rlk_generation.obsolete')), false)
    assert.equal(existsSync(join(fixture.root, 'circuits', 'bin', 'threshold', 'target', 'rlk_generation_limb.obsolete')), false)
    assert.equal(JSON.parse(readFileSync(join(fixture.root, 'circuits', 'bin', '.active-preset.json'), 'utf8')).sourceHash, 'source-hash')
  } finally {
    rmSync(fixture.root, { recursive: true, force: true })
  }
})

test('rejects l-BFV hydration before writing a stamp when an artifact is missing', () => {
  const fixture = hydrationFixture()
  try {
    const missing = requiredLbfvDistMarkers(
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

test('rejects hydration before changing targets when a base source artifact is missing', () => {
  const fixture = hydrationFixture()
  try {
    const target = join(fixture.root, 'circuits', 'bin', CIRCUIT_GROUPS.DKG, 'target', 'pk.json')
    const original = readFileSync(target, 'utf8')
    unlinkSync(join(fixture.outputDir, CIRCUIT_PRESETS.SECURE_16384, 'minimum', 'default', CIRCUIT_GROUPS.DKG, 'pk', 'pk.json'))

    assert.throws(fixture.hydrate, /Cannot hydrate circuits\/bin: missing artifact/)
    assert.equal(readFileSync(target, 'utf8'), original)
    assert.equal(existsSync(join(fixture.root, 'circuits', 'bin', '.active-preset.json')), false)
  } finally {
    rmSync(fixture.root, { recursive: true, force: true })
  }
})
