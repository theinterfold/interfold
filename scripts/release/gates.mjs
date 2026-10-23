// SPDX-License-Identifier: LGPL-3.0-only

import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { join } from 'node:path'

import { ROOT_DIR, fail, readJson } from './core.mjs'

export function verifyPublications(environment = process.env) {
  const required = [
    ['ciphernode image', environment.CIPHERNODE_RESULT],
    ['npm packages', environment.NPM_RESULT],
  ]

  for (const [name, result] of required) {
    if (result !== 'success') {
      fail(`${name} publication did not succeed: ${result || 'missing result'}`)
    }
  }

  const expectedDappnodeResult = environment.IS_PRERELEASE === 'true' ? 'skipped' : 'success'
  if (environment.DAPPNODE_RESULT !== expectedDappnodeResult) {
    fail(`DAppNode result is ${environment.DAPPNODE_RESULT}, expected ${expectedDappnodeResult}`)
  }

  console.log('Every required release publication succeeded.')
}

export function checkReleaseSafeguards(rootDir = ROOT_DIR) {
  // Only this development check needs YAML. Publication CLI commands run without npm dependencies.
  const { parse } = createRequire(import.meta.url)('yaml')
  const release = parse(readFileSync(join(rootDir, '.github/workflows/releases.yml'), 'utf8'))
  const packageJson = readJson(rootDir, 'package.json')
  const job = (name) => {
    if (!release.jobs?.[name]) fail(`release workflow does not contain ${name}`)
    return release.jobs[name]
  }
  const requires = (name, dependencies) => {
    const needs = [job(name).needs].flat()
    for (const dependency of dependencies) {
      if (!needs.includes(dependency)) fail(`${name} must require ${dependency}`)
    }
  }
  const command = (name, text) => {
    if (!job(name).steps?.some((step) => step.run?.split('\n').some((line) => line.trim() === text || line.trim().startsWith(`${text} `))))
      fail(`${name} must execute ${text}`)
  }

  if (release.concurrency?.group !== 'release-promotion-${{ github.repository }}' || release.concurrency?.['cancel-in-progress'] !== false)
    fail('release promotions must be serialized without cancellation')
  if (!/^\d+\.\d+\.\d+$/.test(release.env?.NPM_VERSION ?? '')) fail('release workflow does not pin an exact npm version')
  for (const entry of Object.values(release.jobs)) {
    if (entry.uses === './.github/workflows/ci.yml') fail('release workflow repeats CI that already qualified the main commit')
    for (const operation of [entry, ...(entry.steps ?? [])]) {
      if (operation['continue-on-error']) fail('release workflow must not continue on error')
      if (operation.uses?.startsWith('cachix/cachix-action')) fail('release workflow contains cachix/cachix-action')
      for (const unsafe of ['cargo workspaces publish', 'npm@latest'])
        if (operation.run?.includes(unsafe)) fail(`release workflow contains unsafe operation: ${unsafe}`)
    }
  }
  command('validate-and-prepare', 'node scripts/release/index.mjs prepare')
  for (const publisher of ['build-ciphernode-image-release', 'publish-npm-packages']) {
    requires(publisher, ['release-candidate-gate'])
    if (job(publisher).if !== undefined) fail(`${publisher} must retain implicit dependency success gating`)
  }
  requires('release-candidate-gate', ['validate-and-prepare', 'build-binaries', 'download-circuits'])
  if (job('release-candidate-gate').if !== undefined) fail('release-candidate-gate must retain implicit dependency success gating')
  requires('publication-gate', [
    'validate-and-prepare',
    'build-ciphernode-image-release',
    'publish-npm-packages',
    'build-dappnode-package-release',
  ])
  command('publication-gate', 'node scripts/release/index.mjs verify-publications')
  command('download-circuits', 'pnpm store:circuits verify-release')
  for (const name of ['build-binaries', 'download-circuits']) {
    const uploads = job(name).steps.filter((step) => step.uses?.startsWith('actions/upload-artifact@'))
    if (!uploads.length || uploads.some((step) => step.with?.['if-no-files-found'] !== 'error'))
      fail(`${name} must fail on missing release archives`)
  }
  const binaries = job('build-binaries').strategy?.matrix?.include ?? []
  for (const [asset, features] of Object.entries({
    'interfold-linux-x86_64': '',
    'interfold-macos-aarch64': '',
    'interfold-test-only-skip-proof-aggregation-linux-x86_64': 'test-only-skip-proof-aggregation',
  })) {
    const entries = binaries.filter((entry) => entry.asset === asset)
    if (entries.length !== 1 || entries[0].features !== features)
      fail(`the ${asset} release archive must be built with features: ${features}`)
  }
  command('build-binaries', 'test "$compiled" = "$FEATURES"')
  command('build-binaries', 'case "$ASSET" in interfold-test-only-*) ;; *) exit 1 ;; esac')
  command('publish-npm-packages', 'node scripts/release/index.mjs publish-npm')
  command('publish-npm-packages', 'npm install -g "npm@${NPM_VERSION}"')
  requires('create-github-release', ['publication-gate'])
  const createRelease = job('create-github-release')
  if (createRelease.if?.includes('always()') || !createRelease.if?.includes("needs.publication-gate.result == 'success'"))
    fail('GitHub release creation must require successful publications')
  const steps = createRelease.steps
  const create = steps.findIndex((step) => step.uses?.startsWith('softprops/action-gh-release@'))
  const promote = steps.findIndex((step) => step.run?.startsWith('node scripts/release/index.mjs promote-stable'))
  if (promote < 0 || create <= promote) fail('the stable release must be created after its stable tag is promoted')
  command('create-github-release', 'aliases=(--tag "${CIPHERNODE_IMAGE_NAME}:dev")')

  if (packageJson.scripts['release:tag'] !== 'node scripts/release/index.mjs tag') {
    fail('release:tag does not use the protected release command')
  }
  console.log('Release workflow dependency structure verified (not runtime publication assurance).')
}
