#!/usr/bin/env tsx
// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { execFileSync, execSync } from 'child_process'
import { createHash } from 'crypto'
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'fs'
import { join, relative, resolve, sep } from 'path'
import type { CircuitCommittee, CircuitPreset } from './circuit-constants'
import requiredArtifacts from '../crates/zk-prover/required-artifacts.json'
import requiredLbfvArtifacts from '../crates/zk-prover/required-artifacts-lbfv.json'
import supportedConfigurations from '../crates/zk-prover/supported-configurations.json'

const BRANCH = 'circuit-artifacts'
const ROOT = resolve(__dirname, '..')
const DIST = join(ROOT, 'dist', 'circuits')
const METADATA_FILES = new Set(['.git', 'SOURCE_HASH', 'SHA256SUMS', 'checksums.json'])
// The release matrix is the file that the Rust installer requires, so both read the same pairs.
export const RELEASE_REQUIRED_PAIRS = supportedConfigurations.map(
  ([preset, committee]) => [preset as CircuitPreset, committee as CircuitCommittee] as const,
)

const run = (cmd: string, cwd = ROOT) => execSync(cmd, { encoding: 'utf-8', cwd, stdio: 'pipe' }).trim()
const runV = (cmd: string, cwd = ROOT) => execSync(cmd, { cwd, stdio: 'inherit' })

function copyArtifactsInto(target: string): void {
  for (const preset of readdirSync(DIST)) {
    if (METADATA_FILES.has(preset)) continue
    const presetPath = join(DIST, preset)
    if (!statSync(presetPath).isDirectory()) continue

    for (const committee of readdirSync(presetPath)) {
      const localPair = join(presetPath, committee)
      if (!statSync(localPair).isDirectory()) continue

      const remotePair = join(target, preset, committee)
      if (existsSync(remotePair)) rmSync(remotePair, { recursive: true })
      mkdirSync(join(target, preset), { recursive: true })
      cpSync(localPair, remotePair, { recursive: true })
    }
  }
}

function artifactFiles(dir: string, base = dir): string[] {
  const files: string[] = []
  for (const entry of readdirSync(dir)) {
    if (METADATA_FILES.has(entry)) continue
    const full = join(dir, entry)
    const stat = statSync(full)
    if (stat.isDirectory()) files.push(...artifactFiles(full, base))
    else if (stat.isFile()) files.push(relative(base, full))
  }
  return files.sort()
}

export function refreshChecksums(dir: string): void {
  const sums: Record<string, string> = {}
  const lines: string[] = []

  for (const file of artifactFiles(dir)) {
    const hash = createHash('sha256')
      .update(readFileSync(join(dir, file)))
      .digest('hex')
    sums[file] = hash
    lines.push(`${hash}  ${file}`)
  }

  writeFileSync(join(dir, 'SHA256SUMS'), lines.join('\n') + '\n')
  writeFileSync(
    join(dir, 'checksums.json'),
    JSON.stringify({ algorithm: 'sha256', generated: new Date().toISOString(), files: sums }, null, 2) + '\n',
  )
}

function validateChecksumEntries(dir: string, files: string[], entries: Record<string, unknown>, source: string): void {
  const entryFiles = Object.keys(entries).sort()
  if (entryFiles.join('\n') !== files.join('\n')) {
    throw new Error(`${source} does not cover the complete circuit artifact set`)
  }

  for (const file of files) {
    const expected = entries[file]
    if (typeof expected !== 'string' || !/^[0-9a-f]{64}$/i.test(expected)) {
      throw new Error(`${source} contains an invalid SHA-256 value for ${file}`)
    }

    const fullPath = resolve(dir, file)
    const normalized = relative(dir, fullPath)
    if (normalized !== file || normalized === '..' || normalized.startsWith(`..${sep}`)) {
      throw new Error(`${source} contains an invalid artifact path: ${file}`)
    }

    const actual = createHash('sha256').update(readFileSync(fullPath)).digest('hex')
    if (actual !== expected.toLowerCase()) {
      throw new Error(`${source} hash mismatch for ${file}`)
    }
  }
}

/** Verify both checksum manifests against every non-metadata archive file. */
export function validateArtifactChecksums(dir: string): void {
  const files = artifactFiles(dir)
  const jsonPath = join(dir, 'checksums.json')
  const sumsPath = join(dir, 'SHA256SUMS')
  if (!existsSync(jsonPath) || !existsSync(sumsPath)) {
    throw new Error('Circuit artifact checksums are missing')
  }

  let manifest: { algorithm?: unknown; files?: unknown }
  try {
    manifest = JSON.parse(readFileSync(jsonPath, 'utf8')) as typeof manifest
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    throw new Error(`Invalid checksums.json: ${message}`)
  }
  if (manifest.algorithm !== 'sha256' || typeof manifest.files !== 'object' || manifest.files === null || Array.isArray(manifest.files)) {
    throw new Error('Invalid checksums.json: expected a sha256 files map')
  }
  validateChecksumEntries(dir, files, manifest.files as Record<string, unknown>, 'checksums.json')

  const sums: Record<string, unknown> = {}
  const lines = readFileSync(sumsPath, 'utf8').split(/\r?\n/).filter(Boolean)
  for (const line of lines) {
    const match = /^([0-9a-f]{64}) {2}(.+)$/i.exec(line)
    if (!match || sums[match[2]] !== undefined) {
      throw new Error(`Invalid SHA256SUMS entry: ${line}`)
    }
    sums[match[2]] = match[1]
  }
  validateChecksumEntries(dir, files, sums, 'SHA256SUMS')
}

function stampFiles(dir: string): string[] {
  const stamps: string[] = []
  for (const file of artifactFiles(dir)) {
    if (file.endsWith('.build-stamp.json')) stamps.push(file)
  }
  return stamps
}

// Preset directories that also serve the l-BFV path; the Rust installer applies the same rule.
const LBFV_PRESET_DIRS = new Set(['insecure', 'secure-16384'])

export function requiredArtifactMarkers(preset: string, committee: string): string[] {
  const artifacts = LBFV_PRESET_DIRS.has(preset) ? [...requiredArtifacts, ...requiredLbfvArtifacts] : requiredArtifacts
  return artifacts.map((artifact) => join(preset, committee, artifact))
}

type BuildStamp = {
  preset?: string
  committee?: string
  sourceHash?: string
}

function sourceHashForPair(preset: string, committee: string): string {
  return execFileSync('pnpm', ['tsx', 'scripts/build-circuits.ts', 'hash', '--preset', preset, '--committee', committee], {
    cwd: ROOT,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  }).trim()
}

function validatePair(
  dir: string,
  preset: string,
  committee: string,
  expectedSourceHash: (preset: string, committee: string) => string,
): void {
  const stampFile = join(preset, committee, '.build-stamp.json')
  const stampPath = join(dir, stampFile)
  if (!existsSync(stampPath)) {
    throw new Error(`Missing circuit build stamp: ${stampFile}`)
  }

  let stamp: BuildStamp
  try {
    stamp = JSON.parse(readFileSync(stampPath, 'utf8')) as BuildStamp
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    throw new Error(`Invalid circuit build stamp ${stampFile}: ${message}`)
  }
  if (stamp.preset !== preset || stamp.committee !== committee || !stamp.sourceHash) {
    throw new Error(`Invalid circuit build stamp ${stampFile}: expected preset=${preset}, committee=${committee}, and a sourceHash`)
  }

  const expected = expectedSourceHash(preset, committee)
  if (stamp.sourceHash !== expected) {
    throw new Error(
      `Stale circuit artifacts at ${preset}/${committee}: ` +
        `stamp=${stamp.sourceHash}, expected=${expected}. Rebuild that pair before pushing.`,
    )
  }

  const missing = requiredArtifactMarkers(preset, committee).filter((marker) => !existsSync(join(dir, marker)))
  if (missing.length > 0) {
    throw new Error(`Incomplete circuit artifacts at ${preset}/${committee}: missing ${missing[0]}. Rebuild that pair before pushing.`)
  }
}

function argValue(name: string): string | undefined {
  const arg = process.argv.find((value) => value.startsWith(`${name}=`))
  if (arg) return arg.slice(name.length + 1)

  const index = process.argv.indexOf(name)
  if (index >= 0) return process.argv[index + 1]

  return undefined
}

function validateSourceHash(dir: string, expectedHash: string): void {
  const sourceHashPath = join(dir, 'SOURCE_HASH')
  if (!existsSync(sourceHashPath)) {
    throw new Error('circuit-artifacts branch is missing SOURCE_HASH; cannot verify it matches the released source.')
  }

  const pulledHash = readFileSync(sourceHashPath, 'utf8').trim()
  if (pulledHash !== expectedHash) {
    throw new Error(
      `circuit-artifacts is stale (SOURCE_HASH=${pulledHash}, expected ${expectedHash}). ` +
        'Rebuild and re-push the required preset/committee pairs, then run: pnpm store:circuits push',
    )
  }
}

export function validateReleaseArtifacts(
  dir: string,
  expectedSourceHash: (preset: string, committee: string) => string = sourceHashForPair,
): void {
  for (const [preset, committee] of RELEASE_REQUIRED_PAIRS) {
    validatePair(dir, preset, committee, expectedSourceHash)
  }
}

export function validateArtifactSet(
  dir: string,
  expectedSourceHash: (preset: string, committee: string) => string = sourceHashForPair,
): void {
  const requiredStamps = new Set(RELEASE_REQUIRED_PAIRS.map(([preset, committee]) => join(preset, committee, '.build-stamp.json')))
  const retainedStamps = stampFiles(dir)
  for (const stampFile of retainedStamps) {
    if (!requiredStamps.has(stampFile)) {
      throw new Error(`Unexpected circuit build stamp: ${stampFile}`)
    }
  }
  if (retainedStamps.length !== requiredStamps.size) {
    throw new Error(`Expected exactly ${requiredStamps.size} circuit build stamps, got ${retainedStamps.length}`)
  }
  validateReleaseArtifacts(dir, expectedSourceHash)
}

async function push() {
  if (!existsSync(DIST)) {
    console.error('❌ No artifacts. Run: pnpm build:circuits')
    process.exit(1)
  }

  const replace = process.argv.includes('--replace')
  const hash = run('pnpm tsx scripts/build-circuits.ts hash')
  const remote = run('git remote get-url origin')
  const tmp = join(ROOT, '.tmp-circuits')

  if (existsSync(tmp)) rmSync(tmp, { recursive: true })

  const branchExists = run(`git ls-remote --heads origin ${BRANCH}`).includes(BRANCH)

  if (branchExists) {
    runV(`git clone --depth 1 --branch ${BRANCH} --single-branch ${remote} ${tmp}`)
    if (replace) {
      for (const f of readdirSync(tmp)) if (f !== '.git') rmSync(join(tmp, f), { recursive: true })
    }
  } else {
    mkdirSync(tmp)
    run('git init', tmp)
    run(`git remote add origin ${remote}`, tmp)
    run(`git checkout -b ${BRANCH}`, tmp)
  }

  copyArtifactsInto(tmp)
  validateArtifactSet(tmp)
  writeFileSync(join(tmp, 'SOURCE_HASH'), hash)
  refreshChecksums(tmp)

  run('git add -A', tmp)
  try {
    run(`git commit -m "circuits: ${hash}"`, tmp)
  } catch {
    console.log('✅ No changes')
    rmSync(tmp, { recursive: true })
    return
  }
  runV(`git push origin ${BRANCH}`, tmp)
  console.log(`✅ Pushed (${hash})`)

  rmSync(tmp, { recursive: true })
}

/**
 * Rewrite the published build stamps after a change of the source-hash scheme.
 *
 * The circuit artifacts do not change. The operator supplies the hash that the current tree
 * produced under the previous scheme. That value proves that the published artifacts come from
 * this tree, so the recomputed stamps describe the same build and no rebuild is necessary.
 */
async function restamp() {
  const previousHash = argValue('--expect-source-hash')
  if (!previousHash) {
    console.error('❌ restamp requires --expect-source-hash <hash the current tree produced under the previous scheme>')
    process.exit(1)
  }

  const hash = run('pnpm tsx scripts/build-circuits.ts hash')
  const remote = run('git remote get-url origin')
  const tmp = join(ROOT, '.tmp-circuits')
  if (existsSync(tmp)) rmSync(tmp, { recursive: true })
  runV(`git clone --depth 1 --branch ${BRANCH} --single-branch ${remote} ${tmp}`)

  const published = readFileSync(join(tmp, 'SOURCE_HASH'), 'utf8').trim()
  if (published !== previousHash) {
    console.error(
      `❌ circuit-artifacts records SOURCE_HASH=${published}, not ${previousHash}. That branch holds another build; rebuild it instead.`,
    )
    process.exit(1)
  }
  if (published === hash) {
    console.log('✅ Stamps already match this tree')
    rmSync(tmp, { recursive: true })
    return
  }

  for (const [preset, committee] of RELEASE_REQUIRED_PAIRS) {
    const stampPath = join(tmp, preset, committee, '.build-stamp.json')
    const stamp = JSON.parse(readFileSync(stampPath, 'utf8')) as BuildStamp
    writeFileSync(stampPath, JSON.stringify({ ...stamp, sourceHash: sourceHashForPair(preset, committee) }, null, 2) + '\n')
  }
  writeFileSync(join(tmp, 'SOURCE_HASH'), hash)
  refreshChecksums(tmp)

  // Status columns do not survive the trim in `run`. Name-only listings carry paths alone.
  const touchedArtifacts = [run('git diff --name-only HEAD', tmp), run('git ls-files --others --exclude-standard', tmp)]
    .join('\n')
    .split('\n')
    .map((line) => line.trim())
    .filter((path) => path.length > 0 && !METADATA_FILES.has(path) && !path.endsWith('.build-stamp.json'))
  if (touchedArtifacts.length > 0) {
    console.error(`❌ restamp changed a circuit artifact (${touchedArtifacts[0]}). It may only rewrite build stamps.`)
    process.exit(1)
  }

  validateArtifactSet(tmp)
  run('git add -A', tmp)
  run(`git commit -m "circuits: restamp ${published} -> ${hash}"`, tmp)
  runV(`git push origin ${BRANCH}`, tmp)
  console.log(`✅ Restamped (${published} -> ${hash})`)

  rmSync(tmp, { recursive: true })
}

export function findArtifactRevision(root: string, reference: string, sourceHash: string): string {
  const git = (...args: string[]) => execFileSync('git', args, { cwd: root, encoding: 'utf8' }).trim()
  const revisions = git('rev-list', '--first-parent', reference).split('\n')
  for (const revision of revisions) {
    if (!git('ls-tree', '--name-only', revision, '--', 'SOURCE_HASH')) continue
    if (git('show', `${revision}:SOURCE_HASH`) === sourceHash) return revision
  }
  throw new Error(`No published circuit artifacts match SOURCE_HASH=${sourceHash}. Build and push the required preset/committee pairs.`)
}

async function pull() {
  try {
    run(`git fetch origin ${BRANCH}`)
  } catch (e: any) {
    const isNetworkError =
      e.message?.includes('Could not resolve host') || e.message?.includes('unable to access') || e.message?.includes('Connection refused')
    if (isNetworkError) {
      console.error('❌ Network error fetching branch')
    } else {
      console.error(`❌ Branch '${BRANCH}' not found`)
    }
    process.exit(1)
  }

  const hash = run('pnpm tsx scripts/build-circuits.ts hash')
  const revision = findArtifactRevision(ROOT, `origin/${BRANCH}`, hash)

  if (existsSync(DIST)) rmSync(DIST, { recursive: true })
  mkdirSync(DIST, { recursive: true })

  runV(`git archive ${revision} | tar -x -C "${DIST}"`)
  console.log(`✅ Pulled ${revision} (SOURCE_HASH=${hash}) to ${DIST}`)
}

async function verifyRelease() {
  const expectedHash = argValue('--source-hash') ?? run('pnpm tsx scripts/build-circuits.ts hash')

  try {
    validateSourceHash(DIST, expectedHash)
    validateArtifactSet(DIST)
    validateArtifactChecksums(DIST)
  } catch (error: any) {
    console.error(`❌ ${error.message}`)
    process.exit(1)
  }

  console.log(`✅ circuit-artifacts verified (SOURCE_HASH=${expectedHash}, required chain artifacts present)`)
}

if (require.main === module) {
  const cmd = process.argv[2]
  if (cmd === 'push') push()
  else if (cmd === 'pull') pull()
  else if (cmd === 'verify-release') verifyRelease()
  else if (cmd === 'restamp') restamp()
  else if (cmd === 'checksums') refreshChecksums(resolve(argValue('--dir') ?? DIST))
  else
    console.log(
      'Usage: circuit-artifacts.ts [push [--replace]|pull|verify-release [--source-hash <hash>]|checksums [--dir <path>]|restamp --expect-source-hash <hash>]',
    )
}
