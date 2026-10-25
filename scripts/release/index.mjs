// SPDX-License-Identifier: LGPL-3.0-only

import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { prepareReleaseAssets } from './assets.mjs'
import { fail } from './core.mjs'
import { checkReleaseSafeguards, verifyPublications } from './gates.mjs'
import { prepareRelease, promoteStableTag, tagRelease } from './git.mjs'
import { publishNpmPackage } from './npm.mjs'
import { applyTestReleaseVersion, testReleaseLabel } from './version.mjs'

export { prepareReleaseAssets } from './assets.mjs'
export { ROOT_DIR } from './core.mjs'
export { checkReleaseSafeguards, verifyPublications } from './gates.mjs'
export { prepareRelease, promoteStableTag, tagRelease, verifyReleaseCandidate } from './git.mjs'
export { publishNpmPackage } from './npm.mjs'
export { applyTestReleaseVersion, normalizeVersion, testReleaseLabel, testReleaseVersion, validateReleaseVersion } from './version.mjs'

function releaseOptionsFromEnvironment(environment) {
  const required = {
    candidateSha: environment.RELEASE_CANDIDATE_SHA,
    circuitSourceHash: environment.CIRCUIT_SOURCE_HASH,
    tagName: environment.GITHUB_REF_NAME,
    version: environment.RELEASE_VERSION,
    workflowRunId: environment.GITHUB_RUN_ID,
  }

  for (const [name, value] of Object.entries(required)) {
    if (!value) {
      fail(`prepare-assets requires ${name}`)
    }
  }

  if (environment.RELEASE_TEST === 'true') {
    // A branch test release has no tag push: the tag is created from the version when the release is.
    const label = testReleaseLabel(required.version)
    if (label === undefined) fail(`prepare-assets cannot prepare ${required.version} as a test release`)
    return { ...required, isPrerelease: true, tagName: `v${required.version}`, testRelease: { label, sourceRef: required.tagName } }
  }

  return { ...required, isPrerelease: environment.RELEASE_IS_PRERELEASE === 'true' }
}

export function main(args = process.argv.slice(2), environment = process.env) {
  const [command, ...commandArgs] = args

  switch (command) {
    case 'tag':
      if (commandArgs.length !== 1) fail('usage: pnpm release:tag <version>')
      tagRelease(commandArgs[0])
      break
    case 'prepare':
      if (commandArgs.length !== 0) fail('usage: node scripts/release/index.mjs prepare')
      prepareRelease(environment)
      break
    case 'publish-npm':
      if (commandArgs.length !== 2) fail('usage: node scripts/release/index.mjs publish-npm <package-directory> <dist-tag>')
      publishNpmPackage(commandArgs[0], commandArgs[1])
      break
    case 'verify-publications':
      if (commandArgs.length !== 0) fail('usage: node scripts/release/index.mjs verify-publications')
      verifyPublications(environment)
      break
    case 'prepare-assets':
      if (commandArgs.length !== 0) fail('usage: node scripts/release/index.mjs prepare-assets')
      prepareReleaseAssets(releaseOptionsFromEnvironment(environment))
      break
    case 'promote-stable':
      if (commandArgs.length !== 1) fail('usage: node scripts/release/index.mjs promote-stable <candidate-sha>')
      promoteStableTag(commandArgs[0], environment)
      break
    case 'apply-test-version':
      if (commandArgs.length !== 1) fail('usage: node scripts/release/index.mjs apply-test-version <version>')
      // Only the dispatched test release rewrites the checkout. A tag release builds the committed files.
      if (environment.GITHUB_EVENT_NAME !== 'workflow_dispatch') fail('apply-test-version runs only in a dispatched test release')
      applyTestReleaseVersion(commandArgs[0])
      break
    case 'check':
      if (commandArgs.length !== 0) fail('usage: node scripts/release/index.mjs check')
      checkReleaseSafeguards()
      break
    default:
      fail(
        'usage: node scripts/release/index.mjs <tag|prepare|apply-test-version|publish-npm|verify-publications|prepare-assets|promote-stable|check>',
      )
  }
}

const isCommandLine = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)
if (isCommandLine) {
  try {
    main()
  } catch (error) {
    console.error(`Release command failed: ${error.message}`)
    process.exitCode = 1
  }
}
