// SPDX-License-Identifier: LGPL-3.0-only

import { execFileSync, spawnSync } from 'node:child_process'
import { appendFileSync } from 'node:fs'

import { ROOT_DIR, fail, gitSucceeds, resolveCommit, runGit } from './core.mjs'
import { normalizeVersion, releaseChannel, validateReleaseVersion } from './version.mjs'

/**
 * The branches whose history may contain a release tag: main, and the maintenance branch of the
 * release's minor line (`release/X.Y.x`). The maintenance branch carries patch releases cut from an
 * earlier tag. Both branches must be protected on GitHub.
 */
export function releaseBranches(version) {
  const [major, minor] = normalizeVersion(version).split('.')
  return ['main', `release/${major}.${minor}.x`]
}

export function verifyReleaseCandidate(tagRef, protectedRefs, expectedRef, cwd = ROOT_DIR) {
  const tagCommit = resolveCommit(tagRef, cwd)
  const expectedCommit = resolveCommit(expectedRef, cwd)

  if (tagCommit !== expectedCommit) {
    fail(`tag ${tagRef} resolves to ${tagCommit}, not event commit ${expectedCommit}`)
  }

  const refs = [protectedRefs].flat()
  const inHistory = refs.some((ref) => gitSucceeds(['merge-base', '--is-ancestor', tagCommit, resolveCommit(ref, cwd)], cwd))
  if (!inHistory) {
    fail(`tag commit ${tagCommit} is not in protected history ${refs.join(' or ')}`)
  }

  return tagCommit
}

function writeOutput(name, value, outputFile) {
  appendFileSync(outputFile, `${name}=${value}\n`)
}

export function prepareRelease(environment = process.env, rootDir = ROOT_DIR) {
  const { GITHUB_OUTPUT: outputFile, GITHUB_REF: tagRef, GITHUB_REF_NAME: tagName, GITHUB_SHA: eventSha } = environment

  if (!outputFile || !tagRef || !tagName || !eventSha) {
    fail('prepare requires GITHUB_OUTPUT, GITHUB_REF, GITHUB_REF_NAME, and GITHUB_SHA')
  }

  const version = normalizeVersion(tagName)
  const protectedRefs = []
  for (const branch of releaseBranches(version)) {
    const remoteRef = `refs/remotes/origin/${branch}`
    const refspec = `+refs/heads/${branch}:${remoteRef}`
    // main must exist; the maintenance branch exists only for a minor line with patch releases.
    if (branch === 'main') runGit(['fetch', '--no-tags', 'origin', refspec], rootDir)
    else if (!gitSucceeds(['fetch', '--no-tags', 'origin', refspec], rootDir)) continue
    protectedRefs.push(remoteRef)
  }
  const candidateSha = verifyReleaseCandidate(tagRef, protectedRefs, eventSha, rootDir)
  validateReleaseVersion(version, rootDir)

  const isPrerelease = version.includes('-')
  writeOutput('version', version, outputFile)
  writeOutput('is_prerelease', isPrerelease, outputFile)
  writeOutput('channel', releaseChannel(version), outputFile)
  writeOutput('candidate_sha', candidateSha, outputFile)

  console.log(`Validated v${version} at ${candidateSha} in ${protectedRefs.join(' or ')}.`)
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

  const branches = releaseBranches(version)
  if (!branches.includes(branch)) {
    fail(`run this command on ${branches.join(' or ')}, not ${branch || 'a detached commit'}`)
  }

  runGit(['fetch', '--no-tags', 'origin', `+refs/heads/${branch}:refs/remotes/origin/${branch}`], rootDir)
  const localSha = runGit(['rev-parse', 'HEAD'], rootDir)
  const remoteSha = runGit(['rev-parse', `refs/remotes/origin/${branch}`], rootDir)

  if (localSha !== remoteSha) {
    fail(`local ${branch} is ${localSha}, but origin/${branch} is ${remoteSha}`)
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
