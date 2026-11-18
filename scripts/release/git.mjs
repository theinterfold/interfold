// SPDX-License-Identifier: LGPL-3.0-only

import { execFileSync, spawnSync } from 'node:child_process'
import { appendFileSync } from 'node:fs'

import { ROOT_DIR, fail, gitSucceeds, resolveCommit, runGit } from './core.mjs'
import { normalizeVersion, releaseChannel, validateReleaseVersion } from './version.mjs'

/**
 * The branches whose history may contain a release tag: main, and the maintenance branch of the
 * release's minor line (`releases/X.Y.x`). The maintenance branch carries patch releases cut from an
 * earlier tag. The prefix is `releases/` because the repository has a branch named `release`, and
 * Git cannot also hold refs under `release/`.
 */
export function releaseBranches(version) {
  const [major, minor] = normalizeVersion(version).split('.')
  return ['main', `releases/${major}.${minor}.x`]
}

/** The ruleset rules that make a maintenance branch as trusted as main: changes only through a pull
 * request, and no force push. */
const REQUIRED_BRANCH_RULES = ['pull_request', 'non_fast_forward']

/** The rule types that GitHub rulesets enforce on a branch of the workflow's repository. */
export function githubBranchRules(branch, environment = process.env) {
  const { GITHUB_REPOSITORY: repository, GITHUB_TOKEN: token } = environment
  if (!repository || !token) fail('reading branch rules requires GITHUB_REPOSITORY and GITHUB_TOKEN')
  const output = execFileSync('gh', ['api', `repos/${repository}/rules/branches/${encodeURIComponent(branch)}`, '--jq', '[.[].type]'], {
    encoding: 'utf8',
    env: { ...environment, GH_TOKEN: token },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  return JSON.parse(output)
}

/**
 * The fetched remote refs whose history may contain the tag of `version`. main is always trusted.
 * The maintenance branch is trusted only when it exists and `readBranchRules` confirms the required
 * rules; an error while reading them counts as unprotected.
 */
export function trustedReleaseRefs(version, readBranchRules, rootDir = ROOT_DIR) {
  const refs = []
  for (const branch of releaseBranches(version)) {
    const remoteRef = `refs/remotes/origin/${branch}`
    const refspec = `+refs/heads/${branch}:${remoteRef}`
    if (branch === 'main') {
      runGit(['fetch', '--no-tags', 'origin', refspec], rootDir)
      refs.push(remoteRef)
      continue
    }
    if (!gitSucceeds(['fetch', '--no-tags', 'origin', refspec], rootDir)) continue
    let rules
    try {
      rules = readBranchRules(branch)
    } catch (error) {
      console.warn(`Not trusting ${branch}: its branch rules could not be read (${error.message}).`)
      continue
    }
    const missing = REQUIRED_BRANCH_RULES.filter((rule) => !rules.includes(rule))
    if (missing.length > 0) {
      console.warn(`Not trusting ${branch}: no ruleset enforces ${missing.join(' and ')} on it.`)
      continue
    }
    refs.push(remoteRef)
  }
  return refs
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

export function prepareRelease(
  environment = process.env,
  rootDir = ROOT_DIR,
  readBranchRules = (branch) => githubBranchRules(branch, environment),
) {
  const { GITHUB_OUTPUT: outputFile, GITHUB_REF: tagRef, GITHUB_REF_NAME: tagName, GITHUB_SHA: eventSha } = environment

  if (!outputFile || !tagRef || !tagName || !eventSha) {
    fail('prepare requires GITHUB_OUTPUT, GITHUB_REF, GITHUB_REF_NAME, and GITHUB_SHA')
  }

  const version = normalizeVersion(tagName)
  const protectedRefs = trustedReleaseRefs(version, readBranchRules, rootDir)
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
