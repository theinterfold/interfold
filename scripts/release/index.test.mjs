// SPDX-License-Identifier: LGPL-3.0-only

import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { copyFileSync, cpSync, existsSync, mkdtempSync, mkdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, test } from 'node:test'

import { parse, stringify } from 'yaml'

import {
  ROOT_DIR,
  applyTestReleaseVersion,
  checkReleaseSafeguards,
  normalizeVersion,
  prepareRelease,
  prepareReleaseAssets,
  promoteStableTag,
  publishNpmPackage,
  testReleaseLabel,
  testReleaseVersion,
  validateReleaseVersion,
  verifyPublications,
  verifyReleaseCandidate,
} from './index.mjs'
import { bumpDappnodeVersions, validateDappnodeVersions } from './dappnode.mjs'
import { PACKAGE_FILES, bumpCargoLock, bumpCargoManifest, internalDependencyRange, workspaceVersion } from './version.mjs'
import { changelogForRelease } from './assets.mjs'

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
  const common = { CIPHERNODE_RESULT: 'success', NPM_RESULT: 'success' }
  assert.doesNotThrow(() => verifyPublications({ ...common, DAPPNODE_RESULT: 'success', IS_PRERELEASE: 'false' }))
  assert.doesNotThrow(() => verifyPublications({ ...common, DAPPNODE_RESULT: 'skipped', IS_PRERELEASE: 'true' }))
  assert.throws(() => verifyPublications({ ...common, DAPPNODE_RESULT: 'failure', IS_PRERELEASE: 'false' }), /DAppNode result/)
})

const RELEASE_BINARIES = [
  'interfold-linux-x86_64.tar.gz',
  'interfold-macos-aarch64.tar.gz',
  'interfold-test-only-skip-proof-aggregation-linux-x86_64.tar.gz',
]

test('release assets require the complete binary and circuit set', () => {
  const rootDir = temporaryDirectory('interfold-release-assets')
  const distDir = join(rootDir, 'dist', 'downloads')
  const deploymentsDir = join(rootDir, 'deployments')
  mkdirSync(distDir, { recursive: true })
  mkdirSync(deploymentsDir)

  for (const archive of [...RELEASE_BINARIES, 'circuits-1.2.3.tar.gz']) {
    writeFileSync(join(distDir, archive), archive)
  }
  writeFileSync(join(deploymentsDir, 'manifest.json'), '{}\n')
  writeFileSync(join(rootDir, 'CHANGELOG.md'), '#### [v1.2.3](compare)\n\nCurrent changes.\n\n#### [v1.2.2](compare)\n\nOld changes.\n')

  const options = {
    candidateSha: 'abc123',
    circuitSourceHash: 'circuit-source',
    isPrerelease: false,
    tagName: 'v1.2.3',
    version: '1.2.3',
    workflowRunId: '456',
  }
  prepareReleaseAssets(options, rootDir)

  const notes = readFileSync(join(rootDir, 'release_notes.md'), 'utf8')
  assert.match(notes, /Current changes\./)
  assert.doesNotMatch(notes, /Old changes\./)
  assert.match(notes, /@interfold\/sdk@latest/)
  assert.match(notes, /[0-9a-f]{64} {2}interfold-test-only-skip-proof-aggregation-linux-x86_64\.tar\.gz/)
  assert.deepEqual(JSON.parse(readFileSync(join(rootDir, 'release-assets/release-provenance.json'), 'utf8')), {
    candidateSha: 'abc123',
    circuitSourceHash: 'circuit-source',
    tag: 'v1.2.3',
    workflowRunId: '456',
  })

  rmSync(join(distDir, 'interfold-test-only-skip-proof-aggregation-linux-x86_64.tar.gz'))
  assert.throws(
    () => prepareReleaseAssets(options, rootDir),
    /required release asset is missing: interfold-test-only-skip-proof-aggregation-linux-x86_64\.tar\.gz/,
  )
})

test('stable release notes list the pre-release changes and the upgrade note', () => {
  const rootDir = temporaryDirectory('interfold-release-notes')
  const distDir = join(rootDir, 'dist', 'downloads')
  const deploymentsDir = join(rootDir, 'deployments')
  const notesDir = join(rootDir, 'scripts', 'release', 'notes')
  mkdirSync(distDir, { recursive: true })
  mkdirSync(deploymentsDir)
  mkdirSync(notesDir, { recursive: true })

  for (const archive of [...RELEASE_BINARIES, 'circuits-1.3.0.tar.gz']) {
    writeFileSync(join(distDir, archive), archive)
  }
  writeFileSync(join(deploymentsDir, 'manifest.json'), '{}\n')
  writeFileSync(
    join(rootDir, 'CHANGELOG.md'),
    [
      '#### [v1.3.0](compare)\n\nStable changes.\n',
      '#### [v1.3.0-test.2](compare)\n\nSecond test changes.\n',
      '#### [v1.3.0-test.1](compare)\n\nFirst test changes.\n',
      '#### [v1.2.3](compare)\n\nOld changes.\n',
    ].join('\n'),
  )
  writeFileSync(join(notesDir, '1.3.0.md'), 'Reset each node.\n')

  prepareReleaseAssets(
    {
      candidateSha: 'abc123',
      circuitSourceHash: 'circuit-source',
      isPrerelease: false,
      tagName: 'v1.3.0',
      version: '1.3.0',
      workflowRunId: '456',
    },
    rootDir,
  )

  const notes = readFileSync(join(rootDir, 'release_notes.md'), 'utf8')
  assert.match(notes, /### Upgrade\n\nReset each node\./)
  for (const section of ['Stable changes.', 'Second test changes.', 'First test changes.']) {
    assert.ok(notes.includes(section), section)
  }
  assert.doesNotMatch(notes, /Old changes\./)
})

test('release versions use semantic version syntax', () => {
  assert.equal(normalizeVersion('v1.2.3-beta.1'), '1.2.3-beta.1')
  assert.throws(() => normalizeVersion('release-1.2.3'), /not a semantic version/)
})

test('stable release validates and updates both DAppNode network variants', () => {
  const version = JSON.parse(readFileSync(join(ROOT_DIR, 'package.json'), 'utf8')).version
  assert.equal(validateReleaseVersion(version), version)

  const rootDir = temporaryDirectory('interfold-dappnode-versions')
  mkdirSync(join(rootDir, 'dappnode'))
  for (const file of [
    'dappnode_package.json',
    'package.json',
    'package-lock.json',
    'docker-compose.yml',
    'Dockerfile',
    'package_variants',
  ]) {
    cpSync(join(ROOT_DIR, 'dappnode', file), join(rootDir, 'dappnode', file), { recursive: true })
  }
  bumpDappnodeVersions(rootDir, '0.20.0', '0.11.0')
  assert.doesNotThrow(() => validateDappnodeVersions(rootDir, '0.20.0'))
  assert.equal(JSON.parse(readFileSync(join(rootDir, 'dappnode/dappnode_package.json'), 'utf8')).version, '0.11.0')
  for (const network of ['mainnet', 'sepolia']) {
    const compose = readFileSync(join(rootDir, `dappnode/package_variants/${network}/docker-compose.yml`), 'utf8')
    assert.ok(compose.includes(`image: 'interfold-ciphernode-${network}.dnp.dappnode.eth:0.11.0'`))
  }

  const sepoliaCompose = join(rootDir, 'dappnode/package_variants/sepolia/docker-compose.yml')
  writeFileSync(sepoliaCompose, readFileSync(sepoliaCompose, 'utf8').replace(':0.11.0', ':0.10.0'))
  assert.throws(() => validateDappnodeVersions(rootDir, '0.20.0'), /sepolia.*0\.11\.0/)
})

test('release workflow keeps all promotion safeguards', () => {
  assert.doesNotThrow(() => checkReleaseSafeguards(ROOT_DIR))
})

test('workflow checks read real dependency and condition fields, not comments or method names', () => {
  const root = temporaryDirectory('interfold-release-workflow')
  mkdirSync(join(root, '.github/workflows'), { recursive: true })
  writeFileSync(join(root, 'package.json'), readFileSync(join(ROOT_DIR, 'package.json')))
  const original = readFileSync(join(ROOT_DIR, '.github/workflows/releases.yml'), 'utf8')
  const workflow = parse(original)
  const path = join(root, '.github/workflows/releases.yml')
  workflow.jobs['publish-npm-packages'].needs = ['validate-and-prepare']
  writeFileSync(path, stringify(workflow) + '\n# release-candidate-gate\n')
  assert.throws(() => checkReleaseSafeguards(root), /must require release-candidate-gate/)
  workflow.jobs['publish-npm-packages'].needs.push('release-candidate-gate')
  workflow.jobs['publish-npm-packages'].if = '${{ always() }}'
  writeFileSync(path, stringify(workflow))
  assert.throws(() => checkReleaseSafeguards(root), /implicit dependency success/)
  delete workflow.jobs['publish-npm-packages'].if
  workflow.jobs['create-github-release'].if = '${{ always() }}'
  writeFileSync(path, stringify(workflow))
  assert.throws(() => checkReleaseSafeguards(root), /must require successful publications/)
})

test('release workflow isolates test-only features and checks each compiled archive', () => {
  const root = temporaryDirectory('interfold-release-feature-boundary')
  mkdirSync(join(root, '.github/workflows'), { recursive: true })
  copyFileSync(join(ROOT_DIR, 'package.json'), join(root, 'package.json'))
  const original = readFileSync(join(ROOT_DIR, '.github/workflows/releases.yml'), 'utf8')
  for (const change of [
    (workflow) => {
      workflow.jobs['build-binaries'].strategy.matrix.include[0].features = 'test-only-skip-proof-aggregation'
    },
    (workflow) => {
      workflow.jobs['build-binaries'].strategy.matrix.include.pop()
    },
    (workflow) => {
      for (const step of workflow.jobs['build-binaries'].steps)
        if (step.run) step.run = step.run.replace('test "$compiled" = "$FEATURES"', '# feature check removed')
    },
  ]) {
    const workflow = parse(original)
    change(workflow)
    writeFileSync(join(root, '.github/workflows/releases.yml'), stringify(workflow))
    assert.throws(() => checkReleaseSafeguards(root), /features:|must execute test/)
  }
})

test('publication gate fails on every missing, failed, cancelled or skipped required publisher', () => {
  const common = {
    CIPHERNODE_RESULT: 'success',
    NPM_RESULT: 'success',
    DAPPNODE_RESULT: 'success',
    IS_PRERELEASE: 'false',
  }
  for (const publisher of ['CIPHERNODE_RESULT', 'NPM_RESULT']) {
    for (const result of ['', 'failure', 'cancelled', 'skipped'])
      assert.throws(() => verifyPublications({ ...common, [publisher]: result }), /publication did not succeed/)
  }
  assert.throws(() => verifyPublications({ ...common, DAPPNODE_RESULT: 'skipped' }), /DAppNode result/)
})

test('publication CLI still loads without development dependencies installed', () => {
  const root = temporaryDirectory('interfold-release-no-dependencies')
  const scripts = join(root, 'scripts/release')
  mkdirSync(scripts, { recursive: true })
  for (const file of ['index.mjs', 'assets.mjs', 'core.mjs', 'dappnode.mjs', 'gates.mjs', 'git.mjs', 'npm.mjs', 'version.mjs'])
    copyFileSync(join(ROOT_DIR, 'scripts/release', file), join(scripts, file))
  const result = execFileSync(process.execPath, [realpathSync(join(scripts, 'index.mjs')), 'verify-publications'], {
    cwd: root,
    encoding: 'utf8',
    env: {
      ...process.env,
      CIPHERNODE_RESULT: 'success',
      NPM_RESULT: 'success',
      DAPPNODE_RESULT: 'skipped',
      IS_PRERELEASE: 'true',
    },
  })
  assert.match(result, /Every required release publication succeeded/)
})

describe('branch test releases', () => {
  const SHA = '0123456789abcdef0123456789abcdef01234567'

  // A copy of every file that holds the release version, and of the DAppNode files that a stable version
  // needs. `baseVersion` moves the copy to another current version, for example a stable one.
  function versionFixture(baseVersion) {
    const rootDir = temporaryDirectory('interfold-test-release')
    for (const file of [
      'Cargo.toml',
      'Cargo.lock',
      'package.json',
      'packages/interfold-config/package.json',
      'packages/interfold-contracts/package.json',
      'crates/wasm/package.json',
      'packages/interfold-sdk/package.json',
      'packages/interfold-react/package.json',
      'packages/interfold-mcp/package.json',
      'crates/zk/prover/versions.json',
    ]) {
      mkdirSync(join(rootDir, file, '..'), { recursive: true })
      copyFileSync(join(ROOT_DIR, file), join(rootDir, file))
    }
    cpSync(join(ROOT_DIR, 'dappnode'), join(rootDir, 'dappnode'), {
      recursive: true,
      filter: (source) => !source.includes('node_modules'),
    })
    if (baseVersion) {
      const previous = workspaceVersion(rootDir)
      const write = (file, change) => writeFileSync(join(rootDir, file), change(readFileSync(join(rootDir, file), 'utf8')))
      write('Cargo.toml', (text) => bumpCargoManifest(text, baseVersion))
      write('Cargo.lock', (text) => bumpCargoLock(text, previous, baseVersion))
      for (const file of [...PACKAGE_FILES, 'crates/zk/prover/versions.json'])
        write(file, (text) =>
          text.replace(new RegExp(`("(?:version|required_circuits_version)": ")${previous.replaceAll('.', '\\.')}"`), `$1${baseVersion}"`),
        )
      const wrapper = JSON.parse(readFileSync(join(rootDir, 'dappnode/dappnode_package.json'), 'utf8')).version
      bumpDappnodeVersions(rootDir, baseVersion, wrapper)
    }
    return rootDir
  }

  test('derives a unique SemVer version from the current core version, the label and the commit', () => {
    assert.equal(testReleaseVersion('0.20.0-dev.2', 'lbfv', SHA), '0.20.0-lbfv.g0123456')
    assert.equal(testReleaseVersion('0.20.0', 'lbfv', SHA), '0.20.0-lbfv.g0123456')
    assert.equal(testReleaseLabel('0.20.0-lbfv.g0123456'), 'lbfv')
    for (const version of ['0.20.0', '0.20.0-dev.2', '0.19.0-test.2', '1.0.0-beta.1', '0.20.0-lbfv.1', '0.20.0-lbfv.g012345']) {
      assert.equal(testReleaseLabel(version), undefined, version)
    }
  })

  test('refuses a label that names a stable or dev channel, or that npm could read as a version', () => {
    for (const label of ['latest', 'dev', 'stable', 'main', 'next', 'beta', 'x', 'v1', 'LBFV', 'lbfv.1', 'a-b', '', 'abcdefghijklmnopq'])
      assert.throws(() => testReleaseVersion('0.20.0', label, SHA), /test release label/, label)
    assert.throws(() => testReleaseLabel('0.20.0-dev.g0123456'), /reserved/)
  })

  test('publishes to npm only under the label of the version', () => {
    const rootDir = temporaryDirectory('interfold-test-release-npm')
    const packageDir = join(rootDir, 'package')
    mkdirSync(packageDir)
    writeFileSync(
      join(packageDir, 'package.json'),
      `${JSON.stringify({ name: '@interfold/release-test', version: '1.2.3-lbfv.g0123456' })}\n`,
    )
    const calls = []
    const execute = (command, args) => {
      calls.push(args.join(' '))
      if (args[0] === 'pack')
        return {
          status: 0,
          stdout: JSON.stringify([{ name: '@interfold/release-test', filename: 'a.tgz', integrity: 'sha512-x' }]),
          stderr: '',
        }
      if (args[0] === 'view') return { status: 1, stdout: '', stderr: 'npm ERR! code E404' }
      return { status: 0, stdout: '', stderr: '' }
    }
    for (const tag of ['latest', 'dev', 'other'])
      assert.throws(() => publishNpmPackage(packageDir, tag, { execute, rootDir }), /belongs to the lbfv channel/, tag)
    assert.equal(publishNpmPackage(packageDir, 'lbfv', { execute, rootDir }), 'published')
    assert.ok(calls.some((call) => call.startsWith('publish') && call.includes('--tag lbfv')))
  })

  test('applies the version to every file that the build and the publication read', () => {
    const rootDir = versionFixture()
    const before = readFileSync(join(rootDir, 'Cargo.lock'), 'utf8')
    const previous = JSON.parse(readFileSync(join(rootDir, 'package.json'), 'utf8')).version
    const version = testReleaseVersion(previous, 'lbfv', SHA)
    applyTestReleaseVersion(version, rootDir)

    assert.doesNotThrow(() => validateReleaseVersion(version, rootDir))
    const after = readFileSync(join(rootDir, 'Cargo.lock'), 'utf8')
    assert.ok(after.includes(`version = "${version}"`))
    assert.ok(!after.includes(`version = "${previous}"`), 'a local package kept the previous version')
    // Only the local packages change: every registry package keeps its lines.
    const registry = (lock) => lock.split('\n\n').filter((block) => /^source = /m.test(block))
    assert.deepEqual(registry(after), registry(before))
    assert.throws(() => applyTestReleaseVersion('1.2.3', rootDir), /not a branch test release version/)
  })

  describe('prepare', () => {
    function repository(branch, baseVersion) {
      const rootDir = versionFixture(baseVersion)
      git(rootDir, 'init', '--quiet', '--initial-branch', branch)
      git(rootDir, 'config', 'user.email', 'release@example.test')
      git(rootDir, 'config', 'user.name', 'Release Test')
      git(rootDir, 'add', '.')
      git(rootDir, 'commit', '--quiet', '--message', 'candidate')
      const sha = git(rootDir, 'rev-parse', 'HEAD')
      const outputFile = join(rootDir, '.github-output')
      writeFileSync(outputFile, '')
      const environment = {
        GITHUB_EVENT_NAME: 'workflow_dispatch',
        GITHUB_OUTPUT: outputFile,
        GITHUB_REF: `refs/heads/${branch}`,
        GITHUB_REF_NAME: branch,
        GITHUB_SHA: sha,
        RELEASE_TEST_LABEL: 'lbfv',
      }
      return { environment, outputFile, rootDir, sha }
    }

    test('names the version, the dist-tag and the candidate from the dispatched branch commit', () => {
      const { environment, outputFile, rootDir, sha } = repository('lbfv-branch')
      prepareRelease(environment, rootDir)
      const outputs = Object.fromEntries(
        readFileSync(outputFile, 'utf8')
          .trim()
          .split('\n')
          .map((line) => line.split('=')),
      )
      assert.deepEqual(outputs, {
        version: `${workspaceVersion(rootDir).split('-')[0]}-lbfv.g${sha.slice(0, 7)}`,
        is_prerelease: 'true',
        channel: 'lbfv',
        candidate_sha: sha,
        test_release: 'true',
      })
    })

    test('derives the version from a stable base version as well as from a dev one', () => {
      const { environment, outputFile, rootDir, sha } = repository('lbfv-branch', '1.2.3')
      assert.equal(workspaceVersion(rootDir), '1.2.3')
      prepareRelease(environment, rootDir)
      assert.match(readFileSync(outputFile, 'utf8'), new RegExp(`^version=1\\.2\\.3-lbfv\\.g${sha.slice(0, 7)}$`, 'm'))
    })

    test('refuses main, a tag ref, a moved checkout, and a reserved label', () => {
      const { environment, rootDir } = repository('lbfv-branch')
      for (const [change, message] of [
        [{ GITHUB_REF: 'refs/heads/main' }, /branch other than main/],
        [{ GITHUB_REF: 'refs/tags/v0.20.0-lbfv.g0123456' }, /branch other than main/],
        [{ GITHUB_SHA: SHA }, /not event commit/],
        [{ RELEASE_TEST_LABEL: 'dev' }, /"dev" is reserved/],
        [{ RELEASE_TEST_LABEL: 'latest' }, /"latest" is reserved/],
        [{ RELEASE_TEST_LABEL: '' }, /requires GITHUB_OUTPUT/],
      ])
        assert.throws(() => prepareRelease({ ...environment, ...change }, rootDir), message, JSON.stringify(change))
    })

    test('a tag push never takes the test release shape', () => {
      const { environment, rootDir } = repository('main')
      assert.throws(
        () =>
          prepareRelease(
            {
              ...environment,
              GITHUB_EVENT_NAME: 'push',
              GITHUB_REF: 'refs/tags/v0.20.0-lbfv.g0123456',
              GITHUB_REF_NAME: 'v0.20.0-lbfv.g0123456',
            },
            rootDir,
          ),
        /version shape of a branch test release/,
      )
    })
  })

  test('test release notes and provenance name the branch, and no stable or dev install', () => {
    const rootDir = temporaryDirectory('interfold-test-release-assets')
    const distDir = join(rootDir, 'dist', 'downloads')
    mkdirSync(distDir, { recursive: true })
    mkdirSync(join(rootDir, 'deployments'))
    const version = '1.2.3-lbfv.g0123456'
    for (const archive of [...RELEASE_BINARIES, `circuits-${version}.tar.gz`]) writeFileSync(join(distDir, archive), archive)
    writeFileSync(join(rootDir, 'deployments/manifest.json'), '{}\n')

    prepareReleaseAssets(
      {
        candidateSha: 'abc123',
        circuitSourceHash: 'circuit-source',
        isPrerelease: true,
        tagName: `v${version}`,
        testRelease: { label: 'lbfv', sourceRef: 'lbfv-branch' },
        version,
        workflowRunId: '456',
      },
      rootDir,
    )
    const notes = readFileSync(join(rootDir, 'release_notes.md'), 'utf8')
    assert.match(notes, /test release from the `lbfv-branch` branch/)
    assert.match(notes, /@interfold\/sdk@lbfv/)
    assert.doesNotMatch(notes, /@interfold\/sdk@(latest|dev)/)
    assert.equal(
      JSON.parse(readFileSync(join(rootDir, 'release-assets/release-provenance.json'), 'utf8')).testRelease.sourceRef,
      'lbfv-branch',
    )
  })

  test('the stable tag never moves in a dispatched run', () => {
    assert.throws(
      () => promoteStableTag('HEAD', { GITHUB_EVENT_NAME: 'workflow_dispatch', GITHUB_TOKEN: 'token' }),
      /never moves the stable tag/,
    )
  })

  test('published packages pin the exact test build, and a normal release keeps the caret range', () => {
    assert.equal(internalDependencyRange('0.20.0-lbfv.g0123456'), '0.20.0-lbfv.g0123456')
    assert.equal(internalDependencyRange('0.20.0'), '^0.20.0')
    assert.equal(internalDependencyRange('0.20.0-dev.2'), '^0.20.0-dev.2')
  })

  test('the changelog of a stable release skips test release headings', () => {
    const changelog = [
      '#### [v1.3.0](compare)\n\nStable changes.\n',
      '#### [v1.3.0-lbfv.g0123456](compare)\n\nBranch test changes.\n',
      '#### [v1.3.0-test.1](compare)\n\nFirst test changes.\n',
      '#### [v1.2.3](compare)\n\nOld changes.\n',
    ].join('\n')
    const notes = changelogForRelease(changelog, '1.3.0')
    assert.ok(notes.includes('Stable changes.'))
    assert.ok(notes.includes('First test changes.'))
    assert.doesNotMatch(notes, /Branch test changes\./)
  })

  test('the changelog generator ignores test release tags', () => {
    const { tagPattern } = JSON.parse(readFileSync(join(ROOT_DIR, '.auto-changelog'), 'utf8'))
    const pattern = new RegExp(tagPattern)
    for (const tag of ['v0.20.0', 'v0.20.0-dev.2', 'v0.19.0-test.2', 'v1.0.0-beta.1']) assert.ok(pattern.test(tag), tag)
    for (const tag of ['v0.20.0-lbfv.g0123456', 'stable']) assert.ok(!pattern.test(tag), tag)
  })

  test('workflow checks reject a test release path to the stable names', () => {
    const root = temporaryDirectory('interfold-test-release-workflow')
    mkdirSync(join(root, '.github/workflows'), { recursive: true })
    copyFileSync(join(ROOT_DIR, 'package.json'), join(root, 'package.json'))
    const original = readFileSync(join(ROOT_DIR, '.github/workflows/releases.yml'), 'utf8')
    for (const [change, message] of [
      [(workflow) => (workflow.on.push.branches = ['main']), /tag pushes only/],
      [(workflow) => delete workflow.on.workflow_dispatch, /triggers must be/],
      [(workflow) => (workflow.on.workflow_dispatch.inputs.tag = { type: 'string' }), /only the label input/],
      [
        (workflow) => delete workflow.jobs['publish-npm-packages'].steps.find((step) => step.run?.includes('apply-test-version')).if,
        /only for a test release/,
      ],
      [
        (workflow) => delete workflow.jobs['create-github-release'].steps.find((step) => step.run?.includes('promote-stable')).if,
        /stable tag/,
      ],
      [(workflow) => (workflow.concurrency.group = 'release-promotion-${{ github.repository }}'), /serialized/],
    ]) {
      const workflow = parse(original)
      change(workflow)
      writeFileSync(join(root, '.github/workflows/releases.yml'), stringify(workflow))
      assert.throws(() => checkReleaseSafeguards(root), message)
    }
  })
})
