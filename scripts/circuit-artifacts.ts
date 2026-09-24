#!/usr/bin/env tsx
// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { execFileSync, execSync } from 'child_process'
import { createHash } from 'crypto'
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'fs'
import { join, relative, resolve } from 'path'
import { SUPPORTED_PRESET_COMMITTEE_PAIRS } from './circuit-constants'

const BRANCH = 'circuit-artifacts'
const ROOT = resolve(__dirname, '..')
const DIST = join(ROOT, 'dist', 'circuits')
const METADATA_FILES = new Set(['.git', 'SOURCE_HASH', 'SHA256SUMS', 'checksums.json'])
export const RELEASE_REQUIRED_PAIRS = SUPPORTED_PRESET_COMMITTEE_PAIRS.map(({ preset, committee }) => [preset, committee] as const)

const REQUIRED_BASE_CIRCUITS = [
  'dkg/e_sm_share_computation/e_sm_share_computation',
  'dkg/pk/pk',
  'dkg/share_decryption/share_decryption',
  'dkg/share_encryption/share_encryption',
  'dkg/sk_share_computation/sk_share_computation',
  'threshold/decrypted_shares_aggregation/decrypted_shares_aggregation',
  'threshold/pk_aggregation/pk_aggregation',
  'threshold/pk_generation/pk_generation',
  'threshold/share_decryption/share_decryption',
  'threshold/user_data_encryption/user_data_encryption',
  'threshold/user_data_encryption_ct0/user_data_encryption_ct0',
  'threshold/user_data_encryption_ct1/user_data_encryption_ct1',
] as const

const REQUIRED_AGGREGATION_CIRCUITS = [
  'recursive_aggregation/c2ab_fold/c2ab_fold',
  'recursive_aggregation/c3_fold/c3_fold',
  'recursive_aggregation/c3_fold_kernel/c3_fold_kernel',
  'recursive_aggregation/c3ab_fold/c3ab_fold',
  'recursive_aggregation/c4ab_fold/c4ab_fold',
  'recursive_aggregation/c6_fold/c6_fold',
  'recursive_aggregation/c6_fold_kernel/c6_fold_kernel',
  'recursive_aggregation/decryption_aggregator/decryption_aggregator',
  'recursive_aggregation/dkg_aggregator/dkg_aggregator',
  'recursive_aggregation/node_fold/node_fold',
  'recursive_aggregation/nodes_fold/nodes_fold',
  'recursive_aggregation/nodes_fold_kernel/nodes_fold_kernel',
] as const

const REQUIRED_EVM_AGGREGATION_CIRCUITS = [
  'recursive_aggregation/decryption_aggregator/decryption_aggregator',
  'recursive_aggregation/dkg_aggregator/dkg_aggregator',
] as const

const REQUIRED_VARIANT_CIRCUITS = [
  ...REQUIRED_BASE_CIRCUITS.map((circuit) => join('default', circuit)),
  ...REQUIRED_AGGREGATION_CIRCUITS.map((circuit) => join('default', circuit)),
  ...REQUIRED_BASE_CIRCUITS.map((circuit) => join('evm', circuit)),
  ...REQUIRED_EVM_AGGREGATION_CIRCUITS.map((circuit) => join('evm', circuit)),
  ...REQUIRED_BASE_CIRCUITS.map((circuit) => join('recursive', circuit)),
] as const

const REQUIRED_ARTIFACT_EXTENSIONS = ['.json', '.vk', '.vk_hash'] as const

const run = (cmd: string, cwd = ROOT) => execSync(cmd, { encoding: 'utf-8', cwd, stdio: 'pipe' }).trim()
const runV = (cmd: string, cwd = ROOT) => execSync(cmd, { cwd, stdio: 'inherit' })

export function copyArtifactsInto(target: string, source = DIST): void {
  for (const [preset, committee] of RELEASE_REQUIRED_PAIRS) {
    const localPair = join(source, preset, committee)
    const remotePair = join(target, preset, committee)
    if (existsSync(remotePair)) rmSync(remotePair, { recursive: true })
    mkdirSync(join(target, preset), { recursive: true })
    cpSync(localPair, remotePair, { recursive: true })
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

function refreshChecksums(dir: string): void {
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

function stampFiles(dir: string): string[] {
  const stamps: string[] = []
  for (const file of artifactFiles(dir)) {
    if (file.endsWith('.build-stamp.json')) stamps.push(file)
  }
  return stamps
}

export function requiredArtifactMarkers(preset: string, committee: string): string[] {
  return REQUIRED_VARIANT_CIRCUITS.flatMap((circuit) =>
    REQUIRED_ARTIFACT_EXTENSIONS.map((extension) => join(preset, committee, `${circuit}${extension}`)),
  )
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

  if (existsSync(DIST)) rmSync(DIST, { recursive: true })
  mkdirSync(DIST, { recursive: true })

  runV(`git archive origin/${BRANCH} | tar -x -C "${DIST}"`)
  console.log(`✅ Pulled to ${DIST}`)
}

async function verifyRelease() {
  const expectedHash = argValue('--source-hash') ?? run('pnpm tsx scripts/build-circuits.ts hash')

  try {
    validateSourceHash(DIST, expectedHash)
    validateArtifactSet(DIST)
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
  else
    console.log(
      'Usage: circuit-artifacts.ts [push [--replace]|pull|verify-release [--source-hash <hash>]|restamp --expect-source-hash <hash>]',
    )
}
