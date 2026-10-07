// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { AbiCoder, id, keccak256 } from 'ethers'
import { BFV_PARAMS } from '../packages/interfold-contracts/scripts/protocol/constants'
import { committeeBoundUpdates, NoirCircuitBuilder, normalizeCargoLockForCircuitHash, stripRustTestModules } from './build-circuits'
import { isPresetCommitteeSupported } from './circuit-constants'
import {
  findArtifactRevision,
  RELEASE_REQUIRED_PAIRS,
  requiredArtifactMarkers,
  validateArtifactSet,
  validateReleaseArtifacts,
} from './circuit-artifacts'

function sourceHash(preset: string, committee: string): string {
  return `source:${preset}:${committee}`
}

test('every release pair is a supported build pair', () => {
  assert.ok(RELEASE_REQUIRED_PAIRS.length > 0)
  for (const [preset, committee] of RELEASE_REQUIRED_PAIRS) {
    assert.ok(isPresetCommitteeSupported(preset, committee), `${preset}/${committee} cannot be built`)
  }
})

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

test('checksums command covers exactly the staged circuit configurations', () => {
  const dir = makeCompleteMatrix()
  try {
    for (const preset of ['insecure-512', 'secure-8192']) {
      for (const committee of ['micro', 'small']) {
        rmSync(join(dir, preset, committee), { recursive: true })
      }
    }
    execFileSync('pnpm', ['tsx', 'scripts/circuit-artifacts.ts', 'checksums', '--dir', dir])
    const manifest = JSON.parse(readFileSync(join(dir, 'checksums.json'), 'utf8'))
    assert.equal(manifest.algorithm, 'sha256')
    assert.deepEqual(
      Object.keys(manifest.files).sort(),
      ['insecure-512', 'secure-8192']
        .flatMap((preset) => [...requiredArtifactMarkers(preset, 'minimum'), join(preset, 'minimum', '.build-stamp.json')])
        .sort(),
    )
    assert.equal(
      manifest.files['insecure-512/minimum/default/dkg/pk/pk.vk'],
      '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a',
    )
  } finally {
    rmSync(dir, { recursive: true, force: true })
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

test('circuit hash ignores Rust test modules and tracks everything else', () => {
  const tests = '#[cfg(test)]\nmod tests {\n    #[test]\n    fn checks() {\n        assert!(true);\n    }\n}\n'
  const before = Buffer.from(`pub fn bound() -> u64 {\n    7\n}\n\n${tests}`)
  const edited = (from: string, to: string) => Buffer.from(before.toString().replace(from, to))

  // Editing or deleting a test module leaves the generator output unchanged.
  assert.deepEqual(stripRustTestModules(edited('assert!(true)', 'assert_eq!(1, 1)')), stripRustTestModules(before))
  assert.deepEqual(stripRustTestModules(edited(tests, '')), stripRustTestModules(before))

  // Production code, including code after a test module, still changes the hash.
  assert.notDeepEqual(stripRustTestModules(edited('    7\n', '    8\n')), stripRustTestModules(before))
  assert.notDeepEqual(stripRustTestModules(Buffer.from(`${before}pub fn later() {}\n`)), stripRustTestModules(before))
})

test('pair source hash ignores generated bounds but tracks other Noir config', () => {
  const dir = mkdtempSync(join(tmpdir(), 'interfold-circuit-hash-'))
  const configDir = join(dir, 'circuits', 'lib', 'src', 'configs', 'insecure')
  mkdirSync(configDir, { recursive: true })
  const thresholdPath = join(configDir, 'threshold.nr')
  const dkgPath = join(configDir, 'dkg.nr')
  // `nargo fmt` wraps a long array bound over two lines, and the array type holds a `;` of its own.
  const threshold = (bound: number, quotients: string, l: number) =>
    `pub global PK_GENERATION_E_SM_BOUND: Field = ${bound};\n` +
    `pub global PK_GENERATION_E_SM_QUOTIENT_BOUNDS: [Field; L] =\n    [${quotients}];\n` +
    `pub global L: u32 = ${l};\n`
  writeFileSync(thresholdPath, threshold(10, '1, 2', 2))
  writeFileSync(dkgPath, 'pub global SHARE_COMPUTATION_E_SM_BIT_SECRET: u32 = 28;\n')

  try {
    const builder = new NoirCircuitBuilder(dir, { preset: 'insecure-512', committee: 'micro' })
    const originalHash = builder.computeSourceHash('insecure-512', 'micro')
    writeFileSync(thresholdPath, threshold(20, '3, 4', 2))
    writeFileSync(dkgPath, 'pub global SHARE_COMPUTATION_E_SM_BIT_SECRET: u32 = 30;\n')
    assert.equal(builder.computeSourceHash('insecure-512', 'micro'), originalHash)

    writeFileSync(thresholdPath, threshold(20, '3, 4', 3))
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

test('every pair regenerates all of its C1/C2 bounds, array bounds included', () => {
  const root = join(__dirname, '..')
  for (const [preset, committee] of RELEASE_REQUIRED_PAIRS) {
    for (const { path, generated, updated } of committeeBoundUpdates(root, preset, committee)) {
      const config = updated.replace(/\s+/g, '')
      for (const declaration of generated.match(/^pub global (?:PK_GENERATION|SHARE_COMPUTATION)_[A-Z0-9_]+:.*;$/gm) ?? []) {
        assert.ok(config.includes(declaration.replace(/\s+/g, '')), `${preset}/${committee} ${path}: ${declaration}`)
      }
    }
  }
})

test('every pair source hash tracks shared Noir sources and dependency pins', () => {
  const dir = mkdtempSync(join(tmpdir(), 'interfold-shared-noir-hash-'))
  const sources = [
    'circuits/lib/src/core/dkg/share_encryption.nr',
    'circuits/lib/src/math/commitments.nr',
    'circuits/lib/src/lib.nr',
    'circuits/lib/Nargo.toml',
  ]
  try {
    for (const source of sources) {
      mkdirSync(join(dir, source, '..'), { recursive: true })
      writeFileSync(join(dir, source), 'original')
    }
    const builder = new NoirCircuitBuilder(dir)
    for (const [preset, committee] of RELEASE_REQUIRED_PAIRS) {
      const original = builder.computeSourceHash(preset, committee)
      for (const source of sources) {
        writeFileSync(join(dir, source), 'changed')
        assert.notEqual(builder.computeSourceHash(preset, committee), original, `${preset}/${committee}: ${source}`)
        writeFileSync(join(dir, source), 'original')
        assert.equal(builder.computeSourceHash(preset, committee), original)
      }
    }
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('shared Noir constants change the hash but the active preset does not', () => {
  const dir = mkdtempSync(join(tmpdir(), 'interfold-noir-selection-hash-'))
  const configPath = join(dir, 'circuits/lib/src/configs/default/mod.nr')
  const source = '// preset: insecure-512\npub use super::insecure::threshold;\npub global MAX_MSG_NON_ZERO_COEFFS: u32 = 100;\n'
  try {
    mkdirSync(join(configPath, '..'), { recursive: true })
    writeFileSync(configPath, source)
    const builder = new NoirCircuitBuilder(dir)
    for (const [preset, committee] of RELEASE_REQUIRED_PAIRS) {
      writeFileSync(configPath, source)
      const original = builder.computeSourceHash(preset, committee)
      writeFileSync(configPath, source.replace('insecure-512', 'secure-8192').replace('super::insecure::', 'super::secure::'))
      assert.equal(builder.computeSourceHash(preset, committee), original)
      writeFileSync(configPath, source.replace('= 100;', '= 101;'))
      assert.notEqual(builder.computeSourceHash(preset, committee), original)
    }
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('config generation binds both BFV parameter sets to circuit version v5', () => {
  const dir = mkdtempSync(join(tmpdir(), 'interfold-circuit-version-'))
  const utilsPath = join(dir, 'packages/interfold-contracts/scripts/utils.ts')
  const contractPath = join(dir, 'packages/interfold-contracts/contracts/lib/ActiveCryptoConfig.sol')
  try {
    mkdirSync(join(utilsPath, '..'), { recursive: true })
    mkdirSync(join(contractPath, '..'), { recursive: true })
    copyFileSync(join(__dirname, '../packages/interfold-contracts/scripts/utils.ts'), utilsPath)
    const builder = new NoirCircuitBuilder(dir)
    builder.syncProtocolConfig('insecure-512', 'minimum')
    const contract = readFileSync(contractPath, 'utf8')
    const utils = readFileSync(utilsPath, 'utf8')
    assert.match(contract, /CIRCUIT_VERSION = keccak256\("interfold-bfv-v5"\)/)
    for (const [prefix, params] of [
      ['INSECURE', BFV_PARAMS.insecure512],
      ['SECURE', BFV_PARAMS.secure8192],
    ] as const) {
      const coder = AbiCoder.defaultAbiCoder()
      const paramHash = keccak256(
        coder.encode(
          ['tuple(uint256 degree,uint256 plaintext_modulus,uint256[] moduli,string error1_variance)'],
          [[params.degree, params.plaintextModulus, [...params.moduli], params.error1Variance]],
        ),
      )
      const configId = (version: string) =>
        keccak256(coder.encode(['bytes32', 'bytes32', 'bytes32'], [id('fhe.rs:BFV'), paramHash, id(version)]))
      assert.match(contract, new RegExp(`${prefix}_CONFIG_ID =\\s*${configId('interfold-bfv-v5')}`))
      assert.match(utils, new RegExp(`${prefix}_CONFIG_ID =\\s*"${configId('interfold-bfv-v5')}"`))
    }
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
    {
      group: 'recursive_aggregation',
      name: 'nodes_fold',
      workspace: false,
      expectedTarget: join(dir, 'circuits', 'bin', 'recursive_aggregation', 'nodes_fold', 'target'),
    },
    {
      group: 'recursive_aggregation',
      name: 'c6_fold',
      workspace: false,
      expectedTarget: join(dir, 'circuits', 'bin', 'recursive_aggregation', 'c6_fold', 'target'),
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
      writeFileSync(join(fixture.expectedTarget, `${fixture.name}.vk_tree_hash`), 'stale-tree')

      const pairRoot = join(outputDir, preset, committee)
      for (const variant of ['default', 'evm', 'recursive']) {
        const artifactDir = join(pairRoot, variant, fixture.group, fixture.name)
        mkdirSync(artifactDir, { recursive: true })
        if (variant === 'default') {
          writeFileSync(join(artifactDir, `${fixture.name}.json`), `${fixture.name}-fresh`)
          writeFileSync(join(artifactDir, `${fixture.name}.vk_tree_hash`), 'fresh-tree')
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
      assert.equal(readFileSync(join(fixture.expectedTarget, `${fixture.name}.vk_tree_hash`), 'utf8'), 'fresh-tree')
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

test('cache readiness and checksums include both complete VK-tree anchors', () => {
  const dir = mkdtempSync(join(tmpdir(), 'interfold-vk-tree-markers-'))
  const outputDir = join(dir, 'dist', 'circuits')
  const preset = 'insecure-512'
  const committee = 'minimum'
  const source = 'source-hash'
  try {
    const builder = new NoirCircuitBuilder(dir, { outputDir, preset, committee }) as unknown as {
      requiredDistMarkers: (preset: string, committee: string) => string[]
      requiredBinMarkers: () => string[]
      isDistPresetUpToDate: (preset: string, committee: string, source: string) => boolean
      isBinReadyForPreset: (preset: string, committee: string, source: string) => boolean
      generateChecksumFile: (compiled: never[]) => string
    }
    const distMarkers = builder.requiredDistMarkers(preset, committee)
    const binMarkers = builder.requiredBinMarkers()
    for (const markers of [distMarkers, binMarkers]) {
      assert.equal(markers.filter((file) => file.endsWith('.vk_tree_hash')).length, 2)
      for (const file of markers) {
        mkdirSync(join(file, '..'), { recursive: true })
        writeFileSync(file, Buffer.alloc(32, 1))
      }
    }
    const stamp = JSON.stringify({ preset, committee, sourceHash: source })
    writeFileSync(join(outputDir, preset, committee, '.build-stamp.json'), stamp)
    writeFileSync(join(dir, 'circuits', 'bin', '.active-preset.json'), stamp)
    assert.equal(builder.isDistPresetUpToDate(preset, committee, source), true)
    assert.equal(builder.isBinReadyForPreset(preset, committee, source), true)
    builder.generateChecksumFile([])
    const checksums = JSON.parse(readFileSync(join(outputDir, 'checksums.json'), 'utf8')).files as Record<string, string>
    assert.equal(Object.keys(checksums).filter((file) => file.endsWith('.vk_tree_hash')).length, 2)
    assert.equal(
      readFileSync(join(outputDir, 'SHA256SUMS'), 'utf8')
        .split('\n')
        .filter((line) => line.endsWith('.vk_tree_hash')).length,
      2,
    )
    for (const file of [...distMarkers, ...binMarkers].filter((file) => file.endsWith('.vk_tree_hash'))) {
      assert.ok(existsSync(file))
      unlinkSync(file)
      assert.equal(
        file.startsWith(outputDir)
          ? builder.isDistPresetUpToDate(preset, committee, source)
          : builder.isBinReadyForPreset(preset, committee, source),
        false,
      )
      writeFileSync(file, Buffer.alloc(32, 1))
    }
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
  for (const extension of ['.vk', '.vk_hash', '.vk_tree_hash']) {
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
