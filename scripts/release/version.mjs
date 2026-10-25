// SPDX-License-Identifier: LGPL-3.0-only

import { readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

import { ROOT_DIR, fail, readJson } from './core.mjs'
import { validateDappnodeVersions } from './dappnode.mjs'

export const PACKAGE_FILES = [
  'package.json',
  'packages/interfold-config/package.json',
  'packages/interfold-contracts/package.json',
  'crates/wasm/package.json',
  'packages/interfold-sdk/package.json',
  'packages/interfold-react/package.json',
  'packages/interfold-mcp/package.json',
]

// Guests are independent Cargo workspaces; all five locks record local release versions.
export const CARGO_WORKSPACES = ['.', 'templates/default', 'templates/default/guest']

export function normalizeVersion(input) {
  const version = input.replace(/^v/, '')
  const semanticVersion = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/

  if (!semanticVersion.test(version)) {
    fail(`${version} is not a semantic version`)
  }

  return version
}

// The release channel is the npm distribution tag and the container image alias of a release.
export function releaseChannel(version) {
  return version.includes('-') ? 'dev' : 'latest'
}

// A branch test release is published by an explicit workflow dispatch from a branch. Its version is
// `<core>-<label>.g<short sha>`, for example `0.20.0-lbfv.g1a2b3c4`. The `g` keeps the identifier
// non-numeric: SemVer rejects a numeric identifier with a leading zero, and a short SHA can have one.
const TEST_RELEASE_VERSION = /^\d+\.\d+\.\d+-([a-z]+)\.g[0-9a-f]{7}$/
const TEST_RELEASE_LABEL = /^[a-z]{2,16}$/
// These names already mean something to npm, to the container aliases, or to the install tooling.
const RESERVED_TEST_LABELS = ['latest', 'dev', 'stable', 'main', 'next', 'alpha', 'beta', 'rc', 'canary']

export function validateTestReleaseLabel(label) {
  if (!TEST_RELEASE_LABEL.test(label ?? '')) {
    fail(`test release label "${label}" must be 2 to 16 lowercase letters`)
  }
  if (RESERVED_TEST_LABELS.includes(label)) {
    fail(`test release label "${label}" is reserved`)
  }
  return label
}

/** The label of a branch test release version, or undefined for any other version. */
export function testReleaseLabel(version) {
  const label = TEST_RELEASE_VERSION.exec(version)?.[1]
  return label === undefined ? undefined : validateTestReleaseLabel(label)
}

export function testReleaseVersion(currentVersion, label, sha) {
  validateTestReleaseLabel(label)
  if (!/^[0-9a-f]{40}$/.test(sha ?? '')) {
    fail(`${sha} is not a full commit SHA`)
  }
  const version = `${normalizeVersion(currentVersion).split(/[-+]/)[0]}-${label}.g${sha.slice(0, 7)}`
  testReleaseLabel(version)
  return version
}

export function workspaceVersion(rootDir) {
  const cargoToml = readFileSync(join(rootDir, 'Cargo.toml'), 'utf8')
  const workspacePackage = cargoToml.match(/\[workspace\.package\]([\s\S]*?)(?=\n\[|$)/)?.[1]
  const version = workspacePackage?.match(/^version\s*=\s*"([^"]+)"/m)?.[1]

  if (!version) {
    fail('Cargo.toml does not contain workspace.package.version')
  }

  return version
}

function requireEqual(actual, expected, source) {
  if (actual !== expected) {
    fail(`${source} has ${actual}, expected ${expected}`)
  }
}

export function validateReleaseVersion(versionInput, rootDir = ROOT_DIR) {
  const version = normalizeVersion(versionInput)

  requireEqual(workspaceVersion(rootDir), version, 'Cargo.toml')

  for (const packageFile of PACKAGE_FILES) {
    requireEqual(readJson(rootDir, packageFile).version, version, packageFile)
  }

  requireEqual(
    readJson(rootDir, 'crates/zk/prover/versions.json').required_circuits_version,
    version,
    'crates/zk/prover/versions.json required_circuits_version',
  )

  if (version.includes('-')) {
    return version
  }

  validateDappnodeVersions(rootDir, version)

  return version
}

/** Change only the workspace package and local path dependencies, never registry pins. */
export function bumpCargoManifest(content, version) {
  let section = ''
  let foundVersion = false
  const result = content
    .split('\n')
    .map((line) => {
      if (/^\s*\[/.test(line)) section = line.trim()
      if (section === '[workspace.package]' && /^version\s*=/.test(line)) {
        foundVersion = true
        return line.replace(/"[^"]*"/, `"${version}"`)
      }
      if (section === '[workspace.dependencies]' && /\bpath\s*=\s*"/.test(line))
        return line.replace(/\bversion\s*=\s*"[^"]*"/, `version = "${version}"`)
      return line
    })
    .join('\n')
  if (!foundVersion) fail('Cargo.toml does not contain workspace.package.version')
  return result
}

/** Change only the local packages that have the previous workspace version. Registry packages have a source. */
export function bumpCargoLock(content, previous, version) {
  const entry = new RegExp(`^version = "${previous.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}"$`, 'm')
  return content
    .split('\n\n')
    .map((block) =>
      block.startsWith('[[package]]') && !/^source = /m.test(block) ? block.replace(entry, `version = "${version}"`) : block,
    )
    .join('\n\n')
}

/**
 * Write a branch test release version into the checkout. The files that the build and publication jobs
 * read change; nothing is committed. The manifests must agree on the current version before any change.
 */
export function applyTestReleaseVersion(versionInput, rootDir = ROOT_DIR) {
  const version = normalizeVersion(versionInput)
  if (testReleaseLabel(version) === undefined) {
    fail(`${version} is not a branch test release version`)
  }

  const previous = workspaceVersion(rootDir)
  validateReleaseVersion(previous, rootDir)

  writeFileSync(join(rootDir, 'Cargo.toml'), bumpCargoManifest(readFileSync(join(rootDir, 'Cargo.toml'), 'utf8'), version))
  const lockPath = join(rootDir, 'Cargo.lock')
  writeFileSync(lockPath, bumpCargoLock(readFileSync(lockPath, 'utf8'), previous, version))
  for (const packageFile of PACKAGE_FILES) {
    writeFileSync(join(rootDir, packageFile), `${JSON.stringify({ ...readJson(rootDir, packageFile), version }, null, 2)}\n`)
  }
  const versionsPath = 'crates/zk/prover/versions.json'
  writeFileSync(
    join(rootDir, versionsPath),
    `${JSON.stringify({ ...readJson(rootDir, versionsPath), required_circuits_version: version }, null, 2)}\n`,
  )

  validateReleaseVersion(version, rootDir)
  console.log(`Applied test release version ${version} (was ${previous}); nothing is committed.`)
  return version
}
