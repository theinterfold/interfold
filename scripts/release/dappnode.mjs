// SPDX-License-Identifier: LGPL-3.0-only

import { readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

import { fail, readJson } from './core.mjs'

function variants(rootDir) {
  const directory = join(rootDir, 'dappnode/package_variants')
  const packages = readdirSync(directory, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => {
      const path = join('dappnode/package_variants', entry.name)
      return { path, manifest: readJson(rootDir, join(path, 'dappnode_package.json')) }
    })
  if (!packages.length) fail('DAppNode has no package variants')
  return packages
}

function writeJson(rootDir, path, value) {
  writeFileSync(join(rootDir, path), JSON.stringify(value, null, 2) + '\n')
}

function replace(rootDir, path, pattern, value) {
  const file = join(rootDir, path)
  const source = readFileSync(file, 'utf8')
  if (!pattern.test(source)) fail(`Could not find ${pattern} in ${path}`)
  writeFileSync(file, source.replace(pattern, value))
}

/** Files that a stable version bump changes, for staging. */
export function dappnodeVersionFiles(rootDir) {
  return [
    'dappnode/dappnode_package.json',
    'dappnode/package.json',
    'dappnode/package-lock.json',
    'dappnode/docker-compose.yml',
    'dappnode/Dockerfile',
    ...variants(rootDir).map(({ path }) => join(path, 'docker-compose.yml')),
  ]
}

export function bumpDappnodeVersions(rootDir, upstreamVersion, wrapperVersion) {
  const manifest = readJson(rootDir, 'dappnode/dappnode_package.json')
  manifest.version = wrapperVersion
  manifest.upstreamVersion = upstreamVersion
  writeJson(rootDir, 'dappnode/dappnode_package.json', manifest)

  const npmPackage = readJson(rootDir, 'dappnode/package.json')
  npmPackage.version = wrapperVersion
  writeJson(rootDir, 'dappnode/package.json', npmPackage)

  const lock = readJson(rootDir, 'dappnode/package-lock.json')
  lock.version = wrapperVersion
  lock.packages[''].version = wrapperVersion
  writeJson(rootDir, 'dappnode/package-lock.json', lock)

  replace(rootDir, 'dappnode/docker-compose.yml', /UPSTREAM_VERSION: [^\n]+/, `UPSTREAM_VERSION: ${upstreamVersion}`)
  replace(rootDir, 'dappnode/Dockerfile', /ARG UPSTREAM_VERSION=[^\n]+/, `ARG UPSTREAM_VERSION=${upstreamVersion}`)
  for (const { path, manifest: variant } of variants(rootDir)) {
    replace(rootDir, join(path, 'docker-compose.yml'), /image: '[^']+'/, `image: '${variant.name}:${wrapperVersion}'`)
  }
}

export function validateDappnodeVersions(rootDir, upstreamVersion) {
  const manifest = readJson(rootDir, 'dappnode/dappnode_package.json')
  const npmPackage = readJson(rootDir, 'dappnode/package.json')
  const lock = readJson(rootDir, 'dappnode/package-lock.json')
  for (const [source, actual, expected] of [
    ['DAppNode upstreamVersion', manifest.upstreamVersion, upstreamVersion],
    ['dappnode/package.json', npmPackage.version, manifest.version],
    ['dappnode/package-lock.json', lock.version, manifest.version],
    ['DAppNode lock root package', lock.packages[''].version, manifest.version],
  ]) {
    if (actual !== expected) fail(`${source} has ${actual}, expected ${expected}`)
  }

  const compose = readFileSync(join(rootDir, 'dappnode/docker-compose.yml'), 'utf8')
  const dockerfile = readFileSync(join(rootDir, 'dappnode/Dockerfile'), 'utf8')
  if (!compose.split(/\r?\n/).some((line) => line.trim() === `UPSTREAM_VERSION: ${upstreamVersion}`)) {
    fail(`dappnode/docker-compose.yml does not select upstream version ${upstreamVersion}`)
  }
  if (!dockerfile.split(/\r?\n/).includes(`ARG UPSTREAM_VERSION=${upstreamVersion}`)) {
    fail(`dappnode/Dockerfile does not select upstream version ${upstreamVersion}`)
  }
  for (const { path, manifest: variant } of variants(rootDir)) {
    const file = join(path, 'docker-compose.yml')
    if (!readFileSync(join(rootDir, file), 'utf8').includes(`image: '${variant.name}:${manifest.version}'`)) {
      fail(`${file} does not select ${variant.name}:${manifest.version}`)
    }
  }
}
