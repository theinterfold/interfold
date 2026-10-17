// SPDX-License-Identifier: LGPL-3.0-only

import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import { ROOT_DIR, fail, readJson } from './core.mjs'
import { validateDappnodeVersions } from './dappnode.mjs'

const PACKAGE_FILES = [
  'package.json',
  'packages/interfold-config/package.json',
  'packages/interfold-contracts/package.json',
  'crates/wasm/package.json',
  'packages/interfold-sdk/package.json',
  'packages/interfold-react/package.json',
  'packages/interfold-mcp/package.json',
]

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

function workspaceVersion(rootDir) {
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
    readJson(rootDir, 'crates/zk-prover/versions.json').required_circuits_version,
    version,
    'crates/zk-prover/versions.json required_circuits_version',
  )

  if (version.includes('-')) {
    return version
  }

  validateDappnodeVersions(rootDir, version)

  return version
}
