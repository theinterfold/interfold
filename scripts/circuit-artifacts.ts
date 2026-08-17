#!/usr/bin/env tsx
// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { execSync } from 'child_process'
import { cpSync, existsSync, mkdirSync, readdirSync, rmSync, writeFileSync } from 'fs'
import { join, resolve } from 'path'

const BRANCH = 'circuit-artifacts'
const ROOT = resolve(__dirname, '..')
const DIST = join(ROOT, 'dist', 'circuits')

const run = (cmd: string, cwd = ROOT) => execSync(cmd, { encoding: 'utf-8', cwd, stdio: 'pipe' }).trim()
const runV = (cmd: string, cwd = ROOT) => execSync(cmd, { cwd, stdio: 'inherit' })

async function push() {
  if (!existsSync(DIST)) {
    console.error('❌ No artifacts. Run: pnpm build:circuits')
    process.exit(1)
  }

  const hash = run('pnpm tsx scripts/build-circuits.ts hash --preset insecure-512 --committee all')
  const remote = run('git remote get-url origin')
  const tmp = join(ROOT, '.tmp-circuits')

  if (existsSync(tmp)) rmSync(tmp, { recursive: true })

  const branchExists = run(`git ls-remote --heads origin ${BRANCH}`).includes(BRANCH)

  if (branchExists) {
    runV(`git clone --depth 1 --branch ${BRANCH} --single-branch ${remote} ${tmp}`)
    for (const f of readdirSync(tmp)) if (f !== '.git') rmSync(join(tmp, f), { recursive: true })
  } else {
    mkdirSync(tmp)
    run('git init', tmp)
    run(`git remote add origin ${remote}`, tmp)
    run(`git checkout -b ${BRANCH}`, tmp)
  }

  for (const entry of readdirSync(DIST)) {
    cpSync(join(DIST, entry), join(tmp, entry), { recursive: true })
  }
  writeFileSync(join(tmp, 'SOURCE_HASH'), hash)

  run('git add -A', tmp)
  try {
    run(`git commit -m "circuits: ${hash}"`, tmp)
    runV(`git push origin ${BRANCH} --force`, tmp)
    console.log(`✅ Pushed (${hash})`)
  } catch {
    console.log('✅ No changes')
  }

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

const cmd = process.argv[2]
if (cmd === 'push') push()
else if (cmd === 'pull') pull()
else console.log('Usage: circuit-artifacts.ts [push|pull]')
