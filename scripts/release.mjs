// SPDX-License-Identifier: LGPL-3.0-only

import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { prepareReleaseAssets } from './release/assets.mjs'
import { fail } from './release/core.mjs'
import { checkReleaseSafeguards, verifyPublications } from './release/gates.mjs'
import { prepareRelease, promoteStableTag, tagRelease } from './release/git.mjs'
import { publishNpmPackage } from './release/npm.mjs'

export { prepareReleaseAssets } from './release/assets.mjs'
export { ROOT_DIR } from './release/core.mjs'
export { checkReleaseSafeguards, verifyPublications } from './release/gates.mjs'
export { prepareRelease, promoteStableTag, tagRelease, trustedReleaseRefs, verifyReleaseCandidate } from './release/git.mjs'
export { publishNpmPackage } from './release/npm.mjs'
export { normalizeVersion, validateReleaseVersion } from './release/version.mjs'

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
      if (commandArgs.length !== 0) fail('usage: node scripts/release.mjs prepare')
      prepareRelease(environment)
      break
    case 'publish-npm':
      if (commandArgs.length !== 2) fail('usage: node scripts/release.mjs publish-npm <package-directory> <dist-tag>')
      publishNpmPackage(commandArgs[0], commandArgs[1])
      break
    case 'verify-publications':
      if (commandArgs.length !== 0) fail('usage: node scripts/release.mjs verify-publications')
      verifyPublications(environment)
      break
    case 'prepare-assets':
      if (commandArgs.length !== 0) fail('usage: node scripts/release.mjs prepare-assets')
      prepareReleaseAssets(releaseOptionsFromEnvironment(environment))
      break
    case 'promote-stable':
      if (commandArgs.length !== 1) fail('usage: node scripts/release.mjs promote-stable <candidate-sha>')
      promoteStableTag(commandArgs[0], environment)
      break
    case 'check':
      if (commandArgs.length !== 0) fail('usage: node scripts/release.mjs check')
      checkReleaseSafeguards()
      break
    default:
      fail('usage: node scripts/release.mjs <tag|prepare|publish-npm|verify-publications|prepare-assets|promote-stable|check>')
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
