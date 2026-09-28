// SPDX-License-Identifier: LGPL-3.0-only

import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, test } from 'node:test'

import {
  ROOT_DIR,
  checkReleaseSafeguards,
  normalizeVersion,
  prepareReleaseAssets,
  promoteStableTag,
  publishNpmPackage,
  verifyPublications,
  verifyReleaseCandidate,
} from './release.mjs'

const temporaryDirectories = []

function temporaryDirectory(name) {
  const directory = mkdtempSync(join(tmpdir(), `${name}-`))
  temporaryDirectories.push(directory)
  return directory
}

function git(directory, ...args) {
  return execFileSync('git', args, { cwd: directory, encoding: 'utf8' }).trim()
}

afterEach(() => {
  while (temporaryDirectories.length) {
    rmSync(temporaryDirectories.pop(), { force: true, recursive: true })
  }
})

describe('release candidate ancestry', () => {
  test('accepts only the tagged event commit in protected history', () => {
    const repository = temporaryDirectory('interfold-release-candidate')
    git(repository, 'init', '--quiet', '--initial-branch=main')
    git(repository, 'config', 'user.name', 'Release Test')
    git(repository, 'config', 'user.email', 'release-test@example.invalid')

    writeFileSync(join(repository, 'artifact'), 'candidate\n')
    git(repository, 'add', 'artifact')
    git(repository, 'commit', '--quiet', '-m', 'candidate')
    const candidate = git(repository, 'rev-parse', 'HEAD')
    git(repository, 'tag', '--annotate', 'v1.0.0', '--message', 'v1.0.0', candidate)

    writeFileSync(join(repository, 'artifact'), 'main advanced\n')
    git(repository, 'commit', '--quiet', '-am', 'advance protected branch')

    assert.equal(verifyReleaseCandidate('v1.0.0', 'main', candidate, repository), candidate)
    assert.throws(() => verifyReleaseCandidate('v1.0.0', 'main', 'main', repository), /not event commit/)

    const tree = git(repository, 'rev-parse', `${candidate}^{tree}`)
    const divergent = git(repository, 'commit-tree', tree, '-m', 'divergent candidate')
    git(repository, 'tag', 'v2.0.0', divergent)
    assert.throws(() => verifyReleaseCandidate('v2.0.0', 'main', divergent, repository), /not in protected history/)
  })

  test('promotes the validated commit to the remote stable tag', () => {
    const repository = temporaryDirectory('interfold-stable-source')
    const remote = temporaryDirectory('interfold-stable-remote')
    git(remote, 'init', '--quiet', '--bare')
    git(repository, 'init', '--quiet', '--initial-branch=main')
    git(repository, 'config', 'user.name', 'Release Test')
    git(repository, 'config', 'user.email', 'release-test@example.invalid')
    git(repository, 'remote', 'add', 'origin', remote)

    writeFileSync(join(repository, 'artifact'), 'stable candidate\n')
    git(repository, 'add', 'artifact')
    git(repository, 'commit', '--quiet', '-m', 'stable candidate')
    const candidate = git(repository, 'rev-parse', 'HEAD')

    promoteStableTag(candidate, { ...process.env, GITHUB_TOKEN: 'test-token' }, repository)
    assert.equal(git(remote, 'rev-parse', 'refs/tags/stable'), candidate)
    assert.throws(() => git(repository, 'config', '--local', '--get', 'credential.helper'))
  })
})

test('changelog policy excludes mechanical release commits', () => {
  const config = JSON.parse(readFileSync(join(ROOT_DIR, '.auto-changelog'), 'utf8'))
  const ignoredCommit = new RegExp(config.ignoreCommitPattern)

  assert.equal(config.commitLimit, false)
  assert.equal(config.tagPrefix, 'v')
  assert.match('chore(release): bump version to 1.0.0', ignoredCommit)
  assert.match('chore(release): bump version to 1.0.0 (#10)', ignoredCommit)
  assert.doesNotMatch('feat: current behavior (#11)', ignoredCommit)
})

describe('npm publication recovery', () => {
  function fixture(version = '1.2.3') {
    const rootDir = temporaryDirectory('interfold-npm-publish')
    const packageDir = join(rootDir, 'package')
    mkdirSync(packageDir)
    writeFileSync(join(packageDir, 'package.json'), `${JSON.stringify({ name: '@interfold/release-test', version })}\n`)

    const state = {
      published: false,
      remoteIntegrity: 'sha512-candidate',
      remoteMissing: false,
      tagVersion: version,
      viewError: '',
      packOutput: [
        {
          filename: 'release-test-1.2.3.tgz',
          integrity: 'sha512-candidate',
          name: '@interfold/release-test',
        },
      ],
    }
    const execute = (_command, args, cwd) => {
      switch (args[0]) {
        case 'pack':
          writeFileSync(join(cwd, 'release-test-1.2.3.tgz'), '')
          return result(`${JSON.stringify(state.packOutput)}\n`)
        case 'view':
          if (state.viewError) return result('', 1, state.viewError)
          if (args[2] === 'dist.integrity') {
            return state.remoteMissing ? result('', 1, 'npm error code E404') : result(`${state.remoteIntegrity}\n`)
          }
          return result(`${state.tagVersion}\n`)
        case 'publish':
          state.published = true
          return result('published\n')
        default:
          return result('', 2, `unexpected npm command: ${args.join(' ')}`)
      }
    }

    return { execute, packageDir, rootDir, state }
  }

  function result(stdout, status = 0, stderr = '') {
    return { status, stderr, stdout }
  }

  test('skips matching bytes that already have the requested tag', () => {
    const { execute, packageDir, rootDir, state } = fixture()
    assert.equal(publishNpmPackage(packageDir, 'latest', { execute, rootDir }), 'skipped')
    assert.equal(state.published, false)
    assert.equal(existsSync(join(packageDir, 'release-test-1.2.3.tgz')), false)
  })

  test('accepts npm 12 package-keyed pack output', () => {
    const { execute, packageDir, rootDir, state } = fixture()
    state.packOutput = {
      '@interfold/release-test': {
        filename: 'release-test-1.2.3.tgz',
        integrity: 'sha512-candidate',
        name: '@interfold/release-test',
      },
    }

    assert.equal(publishNpmPackage(packageDir, 'latest', { execute, rootDir }), 'skipped')
    assert.equal(state.published, false)
    assert.equal(existsSync(join(packageDir, 'release-test-1.2.3.tgz')), false)
  })

  test('rejects different bytes at the same package version', () => {
    const { execute, packageDir, rootDir, state } = fixture()
    state.remoteIntegrity = 'sha512-different'
    assert.throws(() => publishNpmPackage(packageDir, 'latest', { execute, rootDir }), /has integrity/)
    assert.equal(state.published, false)
  })

  test('publishes a package only when npm confirms that it is missing', () => {
    const { execute, packageDir, rootDir, state } = fixture()
    state.remoteMissing = true
    assert.equal(publishNpmPackage(packageDir, 'latest', { execute, rootDir }), 'published')
    assert.equal(state.published, true)
  })

  test('does not treat a registry outage as an unpublished package', () => {
    const { execute, packageDir, rootDir, state } = fixture()
    state.viewError = 'npm error code EAI_AGAIN'
    assert.throws(() => publishNpmPackage(packageDir, 'latest', { execute, rootDir }), /EAI_AGAIN/)
    assert.equal(state.published, false)
  })

  test('publishes a pre-release only with the dev tag', () => {
    const { execute, packageDir, rootDir, state } = fixture('1.2.3-dev.1')
    state.remoteMissing = true
    assert.throws(() => publishNpmPackage(packageDir, 'latest', { execute, rootDir }), /belongs to the dev channel/)
    assert.equal(publishNpmPackage(packageDir, 'dev', { execute, rootDir }), 'published')
  })
})

test('publication gate handles stable and pre-release jobs', () => {
  const common = { CIPHERNODE_RESULT: 'success', NPM_RESULT: 'success', SUPPORT_RESULT: 'success' }
  assert.doesNotThrow(() => verifyPublications({ ...common, DAPPNODE_RESULT: 'success', IS_PRERELEASE: 'false' }))
  assert.doesNotThrow(() => verifyPublications({ ...common, DAPPNODE_RESULT: 'skipped', IS_PRERELEASE: 'true' }))
  assert.throws(() => verifyPublications({ ...common, DAPPNODE_RESULT: 'failure', IS_PRERELEASE: 'false' }), /DAppNode result/)
})

test('release assets require the complete binary and circuit set', () => {
  const rootDir = temporaryDirectory('interfold-release-assets')
  const distDir = join(rootDir, 'dist', 'downloads')
  const deploymentsDir = join(rootDir, 'deployments')
  mkdirSync(distDir, { recursive: true })
  mkdirSync(deploymentsDir)

  for (const archive of [
    'interfold-linux-x86_64.tar.gz',
    'interfoldup-linux-x86_64.tar.gz',
    'interfold-macos-aarch64.tar.gz',
    'interfoldup-macos-aarch64.tar.gz',
    'circuits-1.2.3.tar.gz',
  ]) {
    writeFileSync(join(distDir, archive), archive)
  }
  writeFileSync(join(deploymentsDir, 'manifest.json'), '{}\n')
  writeFileSync(join(rootDir, 'CHANGELOG.md'), '#### [v1.2.3](compare)\n\nCurrent changes.\n\n#### [v1.2.2](compare)\n\nOld changes.\n')

  prepareReleaseAssets(
    {
      candidateSha: 'abc123',
      circuitSourceHash: 'circuit-source',
      isPrerelease: false,
      tagName: 'v1.2.3',
      version: '1.2.3',
      workflowRunId: '456',
    },
    rootDir,
  )

  const notes = readFileSync(join(rootDir, 'release_notes.md'), 'utf8')
  assert.match(notes, /Current changes\./)
  assert.doesNotMatch(notes, /Old changes\./)
  assert.match(notes, /@interfold\/sdk@latest/)
  assert.deepEqual(JSON.parse(readFileSync(join(rootDir, 'release-assets/release-provenance.json'), 'utf8')), {
    candidateSha: 'abc123',
    circuitSourceHash: 'circuit-source',
    tag: 'v1.2.3',
    workflowRunId: '456',
  })
})

test('release versions use semantic version syntax', () => {
  assert.equal(normalizeVersion('v1.2.3-beta.1'), '1.2.3-beta.1')
  assert.throws(() => normalizeVersion('release-1.2.3'), /not a semantic version/)
})

test('release workflow keeps all promotion safeguards', () => {
  assert.doesNotThrow(() => checkReleaseSafeguards(ROOT_DIR))
})
