// SPDX-License-Identifier: LGPL-3.0-only

import { execFileSync, spawnSync } from 'node:child_process'
import { appendFileSync } from 'node:fs'

import { ROOT_DIR, fail, gitSucceeds, resolveCommit, runGit } from './core.mjs'
import {
  normalizeVersion,
  releaseChannel,
  testReleaseLabel,
  testReleaseVersion,
  validateReleaseVersion,
  validateTestReleaseLabel,
  workspaceVersion,
} from './version.mjs'

export function verifyReleaseCandidate(tagRef, protectedRef, expectedRef, cwd = ROOT_DIR) {
  const tagCommit = resolveCommit(tagRef, cwd)
  const protectedCommit = resolveCommit(protectedRef, cwd)
  const expectedCommit = resolveCommit(expectedRef, cwd)

  if (tagCommit !== expectedCommit) {
    fail(`tag ${tagRef} resolves to ${tagCommit}, not event commit ${expectedCommit}`)
  }

  if (!gitSucceeds(['merge-base', '--is-ancestor', tagCommit, protectedCommit], cwd)) {
    fail(`tag commit ${tagCommit} is not in protected history ${protectedRef}`)
  }

  return tagCommit
}

function writeOutput(name, value, outputFile) {
  appendFileSync(outputFile, `${name}=${value}\n`)
}

/**
 * A branch test release is the only release that does not need a tag on protected main history. It
 * needs an explicit workflow dispatch from a branch other than main. The version, the npm dist-tag, and
 * the container tags all carry the label, so no test release can take a stable or dev name.
 */
export function prepareTestRelease(environment = process.env, rootDir = ROOT_DIR) {
  const { GITHUB_OUTPUT: outputFile, GITHUB_REF: ref, GITHUB_SHA: eventSha, RELEASE_TEST_LABEL: label } = environment

  if (!outputFile || !ref || !eventSha || !label) {
    fail('a test release requires GITHUB_OUTPUT, GITHUB_REF, GITHUB_SHA, and RELEASE_TEST_LABEL')
  }
  if (!ref.startsWith('refs/heads/') || ref === 'refs/heads/main') {
    fail(`a test release runs from a branch other than main, not ${ref}; release main with a tag`)
  }
  validateTestReleaseLabel(label)

  const candidateSha = resolveCommit('HEAD', rootDir)
  if (candidateSha !== eventSha) {
    fail(`checked out ${candidateSha}, not event commit ${eventSha}`)
  }

  const currentVersion = workspaceVersion(rootDir)
  validateReleaseVersion(currentVersion, rootDir)
  const version = testReleaseVersion(currentVersion, label, candidateSha)

  writeOutput('version', version, outputFile)
  writeOutput('is_prerelease', true, outputFile)
  writeOutput('channel', label, outputFile)
  writeOutput('candidate_sha', candidateSha, outputFile)
  writeOutput('test_release', true, outputFile)

  console.log(`Prepared test release v${version} at ${candidateSha} from ${ref}.`)
  return { candidateSha, isPrerelease: true, version }
}

export function prepareRelease(environment = process.env, rootDir = ROOT_DIR) {
  if (environment.GITHUB_EVENT_NAME === 'workflow_dispatch') {
    return prepareTestRelease(environment, rootDir)
  }

  const { GITHUB_OUTPUT: outputFile, GITHUB_REF: tagRef, GITHUB_REF_NAME: tagName, GITHUB_SHA: eventSha } = environment

  if (!outputFile || !tagRef || !tagName || !eventSha) {
    fail('prepare requires GITHUB_OUTPUT, GITHUB_REF, GITHUB_REF_NAME, and GITHUB_SHA')
  }

  const version = normalizeVersion(tagName)
  if (testReleaseLabel(version) !== undefined) {
    fail(`${version} has the version shape of a branch test release; a tag cannot publish it`)
  }
  runGit(['fetch', '--no-tags', 'origin', '+refs/heads/main:refs/remotes/origin/main'], rootDir)
  const candidateSha = verifyReleaseCandidate(tagRef, 'refs/remotes/origin/main', eventSha, rootDir)
  validateReleaseVersion(version, rootDir)

  const isPrerelease = version.includes('-')
  writeOutput('version', version, outputFile)
  writeOutput('is_prerelease', isPrerelease, outputFile)
  writeOutput('channel', releaseChannel(version), outputFile)
  writeOutput('candidate_sha', candidateSha, outputFile)
  writeOutput('test_release', false, outputFile)

  console.log(`Validated v${version} at ${candidateSha} in origin/main.`)
  return { candidateSha, isPrerelease, version }
}

export function tagRelease(versionInput, rootDir = ROOT_DIR) {
  const version = normalizeVersion(versionInput)
  const tag = `v${version}`

  if (runGit(['status', '--porcelain'], rootDir)) {
    fail('the working tree is not clean')
  }

  let branch
  try {
    branch = runGit(['symbolic-ref', '--quiet', '--short', 'HEAD'], rootDir)
  } catch {
    branch = ''
  }

  if (branch !== 'main') {
    fail(`run this command on main, not ${branch || 'a detached commit'}`)
  }

  runGit(['fetch', '--no-tags', 'origin', '+refs/heads/main:refs/remotes/origin/main'], rootDir)
  const localSha = runGit(['rev-parse', 'HEAD'], rootDir)
  const remoteSha = runGit(['rev-parse', 'refs/remotes/origin/main'], rootDir)

  if (localSha !== remoteSha) {
    fail(`local main is ${localSha}, but origin/main is ${remoteSha}`)
  }

  validateReleaseVersion(version, rootDir)

  if (gitSucceeds(['show-ref', '--verify', '--quiet', `refs/tags/${tag}`], rootDir)) {
    fail(`local tag ${tag} already exists`)
  }

  const remoteTags = runGit(['ls-remote', '--tags', 'origin', `refs/tags/${tag}`, `refs/tags/${tag}^{}`], rootDir)
  if (remoteTags) {
    fail(`remote tag ${tag} already exists`)
  }

  const message = version.includes('-') ? `Pre-release ${version}` : `Release ${version}`
  runGit(['tag', '--annotate', tag, '--message', message, localSha], rootDir)

  try {
    execFileSync('git', ['push', 'origin', `refs/tags/${tag}`], { cwd: rootDir, stdio: 'inherit' })
  } catch (error) {
    runGit(['tag', '--delete', tag], rootDir)
    throw new Error(`could not push ${tag}; the local candidate tag was removed`, { cause: error })
  }

  console.log(`Pushed ${tag} at ${localSha}.`)
  console.log('PR CI must pass before tagging. The release workflow checks builds and publication, not the full test suite.')
}

export function promoteStableTag(candidateSha, environment = process.env, rootDir = ROOT_DIR) {
  if (!environment.GITHUB_TOKEN) {
    fail('promote-stable requires GITHUB_TOKEN')
  }
  if (environment.GITHUB_EVENT_NAME === 'workflow_dispatch') {
    fail('a dispatched test release never moves the stable tag')
  }

  const resolvedCandidate = resolveCommit(candidateSha, rootDir)
  runGit(['tag', '--force', 'stable', resolvedCandidate], rootDir)

  const credentialHelper = '!f() { echo username=x-access-token; echo "password=$GITHUB_TOKEN"; }; f'
  runGit(['config', '--local', '--replace-all', 'credential.helper', credentialHelper], rootDir)

  try {
    execFileSync('git', ['push', 'origin', '+refs/tags/stable:refs/tags/stable', '--no-verify'], {
      cwd: rootDir,
      env: environment,
      stdio: 'inherit',
    })
  } finally {
    spawnSync('git', ['config', '--local', '--unset-all', 'credential.helper'], { cwd: rootDir, stdio: 'ignore' })
  }

  const remoteStable = runGit(['ls-remote', 'origin', 'refs/tags/stable'], rootDir).split(/\s+/)[0]
  if (remoteStable !== resolvedCandidate) {
    fail(`remote stable tag is ${remoteStable || 'missing'}, expected ${resolvedCandidate}`)
  }

  console.log(`Updated stable to ${resolvedCandidate}.`)
}
