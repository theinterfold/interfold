// SPDX-License-Identifier: LGPL-3.0-only

import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { copyFileSync, cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { isPresetCommitteeSupported } from './constants'
import {
  findArtifactRevision,
  findCompatibleRevision,
  installVerifiedArtifacts,
  RELEASE_REQUIRED_PAIRS,
  requiredArtifactMarkers,
  validateArtifactSet,
  validateChecksums,
  validateReleaseArtifacts,
} from './artifacts'

function sourceHash(preset: string, committee: string): string {
  return `source:${preset}:${committee}`
}

test('every release pair is a supported build pair', () => {
  assert.ok(RELEASE_REQUIRED_PAIRS.length > 0)
  for (const [preset, committee] of RELEASE_REQUIRED_PAIRS) {
    assert.ok(isPresetCommitteeSupported(preset, committee), `${preset}/${committee} cannot be built`)
  }
})

test('failed promotion restores the previous verified installation', () => {
  const root = mkdtempSync(join(tmpdir(), 'interfold-artifacts-rollback-'))
  try {
    const dist = join(root, 'installed'),
      backup = join(root, 'backup')
    mkdirSync(dist)
    writeFileSync(join(dist, 'proof-key'), 'previous bytes')
    assert.throws(() => installVerifiedArtifacts(join(root, 'missing'), dist, backup), /ENOENT/)
    assert.equal(readFileSync(join(dist, 'proof-key'), 'utf8'), 'previous bytes')
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('build tooling excludes a disabled pair from the shared policy', () => {
  const dir = mkdtempSync(join(tmpdir(), 'interfold-build-policy-'))
  try {
    const pairs: string[][] = JSON.parse(readFileSync(join(__dirname, 'build-pairs.json'), 'utf8'))
    const allowed = pairs.filter(([preset, committee]) => preset !== 'secure-8192' || committee !== 'micro')
    assert.equal(allowed.length, pairs.length - 1)
    const isolated = join(dir, 'scripts/circuits')
    const contracts = join(dir, 'packages/interfold-contracts')
    mkdirSync(isolated, { recursive: true })
    mkdirSync(contracts, { recursive: true })
    copyFileSync(join(__dirname, 'constants.ts'), join(isolated, 'constants.ts'))
    for (const file of ['bfv.ts', 'crypto-config.json']) {
      copyFileSync(join(__dirname, '../../packages/interfold-contracts', file), join(contracts, file))
    }
    writeFileSync(join(isolated, 'build-pairs.json'), JSON.stringify(allowed))
    const result = JSON.parse(
      execFileSync(
        'pnpm',
        [
          'tsx',
          '-e',
          'const policy = require(process.argv[1]); console.log(JSON.stringify({ supported: policy.isPresetCommitteeSupported("secure-8192", "micro"), pairs: policy.SUPPORTED_PRESET_COMMITTEE_PAIRS }));',
          join(isolated, 'constants.ts'),
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
      for (const committee of ['micro', 'small', 'large']) rmSync(join(dir, preset, committee), { recursive: true })
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

test('partial push publishes the staged catalogue and does not advance the ref if preparation fails', (t) => {
  const seed = makeCompleteMatrix()
  const checkout = mkdtempSync(join(tmpdir(), 'interfold-publish-'))
  t.after(() => {
    for (const dir of [seed, checkout]) rmSync(dir, { recursive: true, force: true })
  })
  const env = {
    ...process.env,
    PATH: `${checkout}:${process.env.PATH}`,
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_AUTHOR_NAME: 'Fixture',
    GIT_COMMITTER_NAME: 'Fixture',
    GIT_AUTHOR_EMAIL: 'fixture@localhost',
    GIT_COMMITTER_EMAIL: 'fixture@localhost',
  }
  const git = (cwd: string, ...args: string[]) => execFileSync('git', args, { cwd, env, encoding: 'utf8' }).trim()
  const store = join(checkout, 'store.git')
  git(seed, 'init', '-q', '-b', 'circuit-artifacts')
  writeFileSync(join(seed, 'vk-commitments.json'), 'old')
  git(seed, 'add', '.')
  git(seed, 'commit', '-qm', 'previous publication')
  git(checkout, 'clone', '-q', '--bare', seed, store)
  git(checkout, 'init', '-q')
  git(checkout, 'remote', 'add', 'origin', store)
  for (const file of [
    'scripts/circuits/artifacts.ts',
    'crates/zk/prover/required-artifacts.json',
    'crates/zk/prover/supported-configurations.json',
  ]) {
    mkdirSync(join(checkout, file, '..'), { recursive: true })
    copyFileSync(join(__dirname, '../..', file), join(checkout, file))
  }
  const pair = 'insecure-64/minimum'
  cpSync(join(seed, pair), join(checkout, 'dist/circuits', pair), { recursive: true })
  mkdirSync(join(checkout, 'circuits'))
  writeFileSync(join(checkout, 'circuits/vk-commitments.json'), 'new')
  const selected = join('dist/circuits', pair, 'fixture-pin')
  writeFileSync(join(checkout, selected), 'new')
  // Stub only the builder. The Rust owner tests real VK genealogy and catalogue derivation.
  writeFileSync(
    join(checkout, 'pnpm'),
    `#!/bin/sh
set -eu
if [ "$1" = --silent ]; then
  if [ "$#" = 3 ]; then echo source; else echo "source:$5:$7"; fi
  exit
fi
test "$1 $2 $3" = 'build:circuits prepare-vk-commitments --output'
test -f "$4/secure-8192/small/.build-stamp.json"
cmp "$4/${pair}/fixture-pin" circuits/vk-commitments.json
cp circuits/vk-commitments.json "$4/vk-commitments.json"
`,
    { mode: 0o755 },
  )
  const push = () =>
    execFileSync(process.execPath, [require.resolve('tsx/cli'), 'scripts/circuits/artifacts.ts', 'push'], {
      cwd: checkout,
      env,
      stdio: 'pipe',
    })
  push()
  assert.equal(git(store, 'show', 'circuit-artifacts:vk-commitments.json'), 'new')
  const head = git(store, 'rev-parse', 'circuit-artifacts')
  writeFileSync(join(checkout, selected), 'incompatible')
  assert.throws(push)
  assert.equal(git(store, 'rev-parse', 'circuit-artifacts'), head)
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
    mkdirSync(join(dir, 'circuits'))
    writeFileSync(join(dir, 'circuits/vk-commitments.json'), 'expected')
    assert.throws(() => findCompatibleRevision(dir, 'HEAD'), /No published circuit artifacts match/)
    writeFileSync(join(dir, 'vk-commitments.json'), 'expected')
    assert.throws(() => findArtifactRevision(dir, 'HEAD', 'requested-source'), /No published circuit artifacts match/)
    writeFileSync(join(dir, 'SOURCE_HASH'), 'requested-source\n')
    commit('requested build')
    writeFileSync(join(dir, 'artifact.json'), '{"rebuilt":true}')
    const rebuilt = commit('same source with updated artifacts')
    assert.equal(findArtifactRevision(dir, 'HEAD', 'requested-source'), rebuilt)
    writeFileSync(join(dir, 'SOURCE_HASH'), 'other-source\n')
    writeFileSync(join(dir, 'vk-commitments.json'), 'unmerged graph')
    const newer = commit('build for another source tree')
    assert.equal(findArtifactRevision(dir, 'HEAD'), newer)
    assert.equal(findCompatibleRevision(dir, 'HEAD'), rebuilt)
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
      JSON.stringify({ preset: 'insecure-64', committee: 'small', sourceHash: sourceHash('secure-8192', 'small') }),
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
