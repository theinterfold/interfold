// SPDX-License-Identifier: LGPL-3.0-only

import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import {
  RELEASE_REQUIRED_PAIRS,
  refreshChecksums,
  requiredArtifactMarkers,
  validateArtifactChecksums,
  validateArtifactSet,
  validateReleaseArtifacts,
} from './circuit-artifacts'

const REQUIRED_LBFV_MARKERS = [
  ...['default', 'evm', 'recursive'].flatMap((variant) =>
    [
      'lbfv_pk_generation',
      'lbfv_pk_generation_limb',
      'lbfv_pk_aggregation',
      'rlk_generation',
      'rlk_generation_limb',
      'rlk_aggregation',
    ].flatMap((circuit) =>
      ['.json', '.vk', '.vk_hash'].map((extension) =>
        join('secure-16384', 'minimum', variant, 'threshold', circuit, `${circuit}${extension}`),
      ),
    ),
  ),
  ...[
    'lbfv_generation_fold',
    'lbfv_generation_fold_kernel',
    'node_fold_v2',
    'nodes_fold_v2',
    'nodes_fold_v2_kernel',
    'lbfv_aggregation_fold',
    'lbfv_aggregation_fold_kernel',
    'dkg_aggregator_v2',
  ].flatMap((circuit) =>
    ['.json', '.vk', '.vk_hash'].map((extension) =>
      join('secure-16384', 'minimum', 'default', 'recursive_aggregation', circuit, `${circuit}${extension}`),
    ),
  ),
  ...['.json', '.vk', '.vk_hash'].map((extension) =>
    join('secure-16384', 'minimum', 'evm', 'recursive_aggregation', 'dkg_aggregator_v2', `dkg_aggregator_v2${extension}`),
  ),
]

function sourceHash(preset: string, committee: string): string {
  return `source:${preset}:${committee}`
}

test('every release pair is a supported build pair', () => {
  assert.ok(RELEASE_REQUIRED_PAIRS.length > 0)
  for (const [preset, committee] of RELEASE_REQUIRED_PAIRS) {
    assert.ok(isPresetCommitteeSupported(preset, committee), `${preset}/${committee} cannot be built`)
  }
})

test('build tooling excludes a disabled pair from the shared policy', () => {
  const dir = mkdtempSync(join(tmpdir(), 'interfold-build-policy-'))
  try {
    const pairs: string[][] = JSON.parse(readFileSync(join(__dirname, 'build-pairs.json'), 'utf8'))
    const allowed = pairs.filter(([preset, committee]) => preset !== 'secure-8192' || committee !== 'micro')
    assert.equal(allowed.length, pairs.length - 1)
    copyFileSync(join(__dirname, 'constants.ts'), join(dir, 'constants.ts'))
    writeFileSync(join(dir, 'build-pairs.json'), JSON.stringify(allowed))
    const result = JSON.parse(
      execFileSync(
        'pnpm',
        [
          'tsx',
          '-e',
          'const policy = require(process.argv[1]); console.log(JSON.stringify({ supported: policy.isPresetCommitteeSupported("secure-8192", "micro"), pairs: policy.SUPPORTED_PRESET_COMMITTEE_PAIRS }));',
          join(dir, 'constants.ts'),
        ],
        { encoding: 'utf8' },
      ),
    )
    assert.equal(result.supported, false)
    assert.deepEqual(
      result.pairs,
      allowed.map(([preset, committee]) => ({ preset, committee })),
    )
  } finally {
    rmSync(dir, { recursive: true, force: true })
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
    for (const preset of ['insecure-64', 'secure-8192']) {
      for (const committee of ['micro', 'small']) rmSync(join(dir, preset, committee), { recursive: true })
    }
    execFileSync('pnpm', ['tsx', 'scripts/circuits/artifacts.ts', 'checksums', '--dir', dir])
    const manifest = JSON.parse(readFileSync(join(dir, 'checksums.json'), 'utf8'))
    assert.equal(manifest.algorithm, 'sha256')
    assert.deepEqual(
      Object.keys(manifest.files).sort(),
      ['insecure-64', 'secure-8192']
        .flatMap((preset) => [...requiredArtifactMarkers(preset, 'minimum'), join(preset, 'minimum', '.build-stamp.json')])
        .sort(),
    )
    assert.equal(
      manifest.files['insecure-64/minimum/default/dkg/pk/pk.vk'],
      '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a',
    )
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('release verification refuses the checksum manifests that a node refuses', () => {
  const dir = makeCompleteMatrix()
  try {
    execFileSync('pnpm', ['tsx', 'scripts/circuits/artifacts.ts', 'checksums', '--dir', dir])
    validateChecksums(dir)
    const manifestPath = join(dir, 'checksums.json')
    const manifest = readFileSync(manifestPath, 'utf8')
    const [first] = Object.keys(JSON.parse(manifest).files).filter((file) => !file.endsWith('.build-stamp.json'))
    const edit = (change: (files: Record<string, string>) => void) => {
      const parsed = JSON.parse(manifest)
      change(parsed.files)
      writeFileSync(manifestPath, JSON.stringify(parsed))
    }
    edit((files) => delete files[first])
    assert.throws(() => validateChecksums(dir), /does not list/)
    edit((files) => (files[first] = '0'.repeat(64)))
    assert.throws(() => validateChecksums(dir), /wrong digest/)
    edit((files) => (files['../outside'] = files[first]))
    assert.throws(() => validateChecksums(dir), /invalid path/)
    edit((files) => (files['insecure-64/minimum/absent.json'] = files[first]))
    assert.throws(() => validateChecksums(dir), /missing file/)
    edit(() => {})
    unlinkSync(manifestPath)
    assert.throws(() => validateChecksums(dir), /checksums.json is missing/)
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
    assert.equal(findArtifactRevision(dir, 'HEAD'), newer)
    assert.equal(findArtifactRevision(dir, 'HEAD', 'requested-source'), rebuilt)
    assert.equal(findArtifactRevision(dir, 'HEAD', 'other-source'), newer)
    assert.throws(() => findArtifactRevision(dir, 'HEAD', 'unpublished-source'), /No published circuit artifacts match/)
    assert.equal(git('rev-parse', 'HEAD'), newer)
    assert.equal(git('status', '--porcelain'), '')
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

test('accepts checksum manifests that cover the complete artifact set', () => {
  const dir = makeCompleteMatrix()
  try {
    refreshChecksums(dir)
    assert.doesNotThrow(() => validateArtifactChecksums(dir))
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('rejects an artifact modified after checksum generation', () => {
  const dir = makeCompleteMatrix()
  try {
    refreshChecksums(dir)
    const marker = requiredArtifactMarkers('secure-8192', 'small')[0]
    writeFileSync(join(dir, marker), 'modified')
    assert.throws(() => validateArtifactChecksums(dir), /hash mismatch/)
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
      JSON.stringify({ preset: 'insecure', committee: 'small', sourceHash: sourceHash('secure-8192', 'small') }),
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

test('rejects every missing user-data encryption child artifact', () => {
  const childMarkers = requiredArtifactMarkers('insecure', 'minimum').filter((artifact) =>
    /recursive\/threshold\/ct[01]_(?:chunk|eval|pk_ct)/.test(artifact),
  )
  assert.equal(childMarkers.length, 16 * 3)

  for (const marker of childMarkers) {
    const dir = makeCompleteMatrix()
    try {
      unlinkSync(join(dir, marker))
      assert.throws(() => validateReleaseArtifacts(dir, sourceHash), /Incomplete circuit artifacts/)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  }
})

test('requires l-BFV row artifacts only for secure-16384', () => {
  const secureMarkers = requiredArtifactMarkers('secure-16384', 'minimum').filter((artifact) => REQUIRED_LBFV_MARKERS.includes(artifact))
  assert.deepEqual(secureMarkers.sort(), REQUIRED_LBFV_MARKERS.toSorted())

  const unsupportedMarkers = requiredArtifactMarkers('secure-8192', 'minimum').filter((artifact) =>
    REQUIRED_LBFV_MARKERS.includes(artifact),
  )
  assert.deepEqual(unsupportedMarkers, [])
})

test('rejects every missing secure-16384 l-BFV row artifact', () => {
  for (const marker of REQUIRED_LBFV_MARKERS) {
    const dir = makeCompleteMatrix()
    try {
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
