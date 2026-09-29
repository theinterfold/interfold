// SPDX-License-Identifier: LGPL-3.0-only

import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import { ROOT_DIR, fail, readJson } from './core.mjs'

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

  const dappnodePackage = readJson(rootDir, 'dappnode/dappnode_package.json')
  const npmPackage = readJson(rootDir, 'dappnode/package.json')
  const npmLock = readJson(rootDir, 'dappnode/package-lock.json')
  const compose = readFileSync(join(rootDir, 'dappnode/docker-compose.yml'), 'utf8')
  const dockerfile = readFileSync(join(rootDir, 'dappnode/Dockerfile'), 'utf8')

  requireEqual(dappnodePackage.upstreamVersion, version, 'DAppNode upstreamVersion')
  requireEqual(npmPackage.version, dappnodePackage.version, 'dappnode/package.json')
  requireEqual(npmLock.version, dappnodePackage.version, 'dappnode/package-lock.json')
  requireEqual(npmLock.packages[''].version, dappnodePackage.version, 'DAppNode lock root package')

  if (!compose.includes(`UPSTREAM_VERSION: ${version}`)) {
    fail(`dappnode/docker-compose.yml does not select upstream version ${version}`)
  }
  if (!compose.includes(`ciphernode.interfold-ciphernode.public.dappnode.eth:${dappnodePackage.version}`)) {
    fail(`dappnode/docker-compose.yml does not select wrapper version ${dappnodePackage.version}`)
  }
  if (!dockerfile.includes(`ARG UPSTREAM_VERSION=${version}`)) {
    fail(`dappnode/Dockerfile does not select upstream version ${version}`)
  }

  return version
}
