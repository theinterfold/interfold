// SPDX-License-Identifier: LGPL-3.0-only

import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import { ROOT_DIR, fail, readJson } from './core.mjs'

export function verifyPublications(environment = process.env) {
  const required = [
    ['ciphernode image', environment.CIPHERNODE_RESULT],
    ['e3-support image', environment.SUPPORT_RESULT],
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

function jobSource(workflow, jobName) {
  const start = workflow.indexOf(`\n  ${jobName}:`)
  if (start < 0) {
    fail(`release workflow does not contain ${jobName}`)
  }
  const next = workflow.slice(start + 1).search(/\n  [A-Za-z0-9_-]+:/)
  return next < 0 ? workflow.slice(start) : workflow.slice(start, start + 1 + next)
}

function requireText(source, text, message) {
  if (!source.includes(text)) {
    fail(message)
  }
}

export function checkReleaseSafeguards(rootDir = ROOT_DIR) {
  const release = readFileSync(join(rootDir, '.github/workflows/releases.yml'), 'utf8')
  const bump = readFileSync(join(rootDir, 'scripts/bump-versions.ts'), 'utf8')
  const packageJson = readJson(rootDir, 'package.json')

  requireText(release, 'node scripts/release.mjs prepare', 'the release tag is not bound to main history')
  requireText(release, 'group: release-promotion-${{ github.repository }}', 'release promotions can overlap')

  if (release.includes('uses: ./.github/workflows/ci.yml')) {
    fail('release workflow repeats CI that already qualified the main commit')
  }

  for (const unsafeText of ['continue-on-error: true', 'cachix/cachix-action', 'cargo workspaces publish', 'npm@latest']) {
    if (release.includes(unsafeText)) {
      fail(`release workflow contains unsafe operation: ${unsafeText}`)
    }
  }

  if (!/^  NPM_VERSION: '\d+\.\d+\.\d+'$/m.test(release)) {
    fail('release workflow does not pin an exact npm version')
  }

  for (const publisher of ['build-ciphernode-image-release', 'build-e3-support-release', 'publish-npm-packages']) {
    requireText(jobSource(release, publisher), 'release-candidate-gate', `${publisher} can publish before candidate qualification`)
  }

  const candidateGate = jobSource(release, 'release-candidate-gate')
  requireText(candidateGate, 'validate-and-prepare', 'release artifacts are not bound to the validated main commit')
  requireText(candidateGate, 'build-binaries', 'publication can start without release binaries')
  requireText(candidateGate, 'download-circuits', 'publication can start without source-matched circuits')

  requireText(release, 'Required circuit-artifacts branch is missing', 'missing circuit artifacts do not fail closed')
  requireText(release, 'if-no-files-found: error', 'missing release archives do not fail artifact upload')
  requireText(release, 'node scripts/release.mjs publish-npm', 'npm publication cannot resume safely')
  requireText(release, 'aliases=(--tag "${image}:dev")', 'a stable release leaves the dev container aliases behind')
  requireText(
    jobSource(release, 'publish-npm-packages'),
    'npm install -g "npm@${NPM_VERSION}"',
    'npm publication does not install the pinned npm version',
  )

  const createRelease = jobSource(release, 'create-github-release')
  requireText(createRelease, 'publication-gate', 'GitHub release creation does not require all publications')
  if (createRelease.includes('always()')) {
    fail('GitHub release creation can bypass a failed dependency')
  }
  if (createRelease.indexOf('- name: Create GitHub Release') < createRelease.indexOf('- name: Update stable tag')) {
    fail('the stable release is created before its aliases and stable tag are promoted')
  }

  if (/git tag (?:-a|--annotate)|git push .*refs\/tags/.test(bump)) {
    fail('the version bump script still creates or pushes a release tag')
  }
  requireText(bump, 'this.checkReleaseBranch()', 'the version bump can commit directly on a protected branch')

  if (packageJson.scripts['release:tag'] !== 'node scripts/release.mjs tag') {
    fail('release:tag does not use the protected release command')
  }

  console.log('Release promotion safeguards are fail closed.')
}
