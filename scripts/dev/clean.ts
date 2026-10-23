#!/usr/bin/env tsx
// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { execFileSync } from 'node:child_process'
import { existsSync, lstatSync, readdirSync, rmSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'

import prompts from 'prompts'

export interface CleanOptions {
  skipNode?: boolean
  skipCrates?: boolean
  skipContracts?: boolean
  interactive?: boolean
  dryRun?: boolean
}

// Application/operator state has a different lifecycle from rebuildable output.
const STATE_DIRECTORIES = new Set(['.git', '.interfold', 'database', 'broadcast', 'ignition', 'deployments'])

export function planClean(rootDir: string, options: CleanOptions = {}): string[] {
  // The index, not HEAD, also protects newly staged files. Failure must stop deletion.
  const tracked = execFileSync('git', ['ls-files', '-z', '--cached'], { cwd: rootDir, encoding: 'utf8' }).split('\0').filter(Boolean)
  const trackedFiles = new Set(tracked)
  const protectedPaths = new Set(tracked)
  for (const file of tracked) {
    for (let parent = dirname(file); parent !== '.'; parent = dirname(parent)) protectedPaths.add(parent)
  }

  const candidates = new Set<string>()
  const add = (parent: string, names: string[]) => names.forEach((name) => candidates.add(join(parent, name)))
  for (const file of tracked) {
    const parent = dirname(file)
    if (!options.skipNode && file.split('/').pop() === 'package.json') add(parent, ['node_modules', 'dist', '.pnpm-store'])
    if (!options.skipCrates && file.split('/').pop() === 'Cargo.toml') add(parent, ['target'])
    if (!options.skipContracts && /(^|\/)hardhat\.config\.[cm]?[jt]s$/.test(file)) add(parent, ['artifacts', 'cache', 'out', 'types'])
  }

  function safeAncestors(path: string): boolean {
    const parts = path.split('/')
    let parent = rootDir
    for (const part of parts.slice(0, -1)) {
      if (part === '.') continue
      parent = join(parent, part)
      if (STATE_DIRECTORIES.has(part) || !existsSync(parent) || lstatSync(parent).isSymbolicLink() || existsSync(join(parent, '.git')))
        return false
    }
    return true
  }

  function select(path: string, nested = false): { removable: boolean; paths: string[] } {
    const full = join(rootDir, path)
    const stat = lstatSync(full, { throwIfNoEntry: false })
    if (!stat) return { removable: !protectedPaths.has(path), paths: [] }
    if (STATE_DIRECTORIES.has(path.split('/').pop()!) || trackedFiles.has(path)) return { removable: false, paths: [] }
    // Unlink children of a physical output tree, never follow them or remove a linked output root.
    if (stat.isSymbolicLink()) {
      const removable = nested && !protectedPaths.has(path)
      return { removable, paths: removable ? [path] : [] }
    }
    if (stat.isFile()) return { removable: true, paths: [path] }
    if (!stat.isDirectory()) return { removable: false, paths: [] }
    if (existsSync(join(full, '.git'))) return { removable: false, paths: [] }
    const children = readdirSync(full)
      .sort()
      .map((name) => select(join(path, name), true))
    if (!protectedPaths.has(path) && children.every((child) => child.removable)) return { removable: true, paths: [path] }
    return { removable: false, paths: children.flatMap((child) => child.paths) }
  }

  const paths = [...candidates]
    .sort()
    .filter(safeAncestors)
    .flatMap((path) => select(path).paths)
  return [...new Set(paths)].filter((path, _, all) => !all.some((parent) => path.startsWith(`${parent}/`)))
}

export async function clean(rootDir: string, options: CleanOptions = {}): Promise<string[]> {
  const paths = planClean(rootDir, options)
  if (options.dryRun) {
    paths.forEach((path) => console.log(path))
    console.log('Dry run complete — no files deleted.')
    return paths
  }
  if (options.interactive && paths.length) {
    const { proceed } = await prompts({
      type: 'confirm',
      name: 'proceed',
      message: `Remove ${paths.length} build output paths?`,
      initial: false,
    })
    if (!proceed) return []
  }
  for (const path of paths) rmSync(join(rootDir, path), { recursive: true, force: true })
  console.log(`Removed ${paths.length} build output paths. Tracked files and operator state were preserved.`)
  return paths
}

function main(): void {
  const options: CleanOptions = {}
  const flags: Record<string, keyof CleanOptions> = {
    '--skip-node': 'skipNode',
    '--skip-crates': 'skipCrates',
    '--skip-contracts': 'skipContracts',
    '--interactive': 'interactive',
    '-i': 'interactive',
    '--dry-run': 'dryRun',
    '-n': 'dryRun',
  }
  for (const arg of process.argv.slice(2)) {
    if (arg === '--help' || arg === '-h') {
      console.log(`Usage: pnpm clean [--skip-node] [--skip-crates] [--skip-contracts] [--interactive|-i] [--dry-run|-n]
Removes rebuildable outputs beside tracked package/Cargo/Hardhat manifests.
Never removes tracked files, operator state, nested repositories, or linked output roots.
Internal output symlinks are unlinked without following their targets.
--skip-node       Keep node_modules, dist, .pnpm-store
--skip-crates     Keep target directories (fixtures are always preserved)
--skip-contracts  Keep artifacts, cache, out, types (deployments are always preserved)`)
      return
    }
    if (!flags[arg]) throw new Error(`Unknown option: ${arg}. Use --help for usage.`)
    options[flags[arg]] = true
  }
  clean(resolve(__dirname, '../..'), options).catch((error) => {
    console.error(error)
    process.exitCode = 1
  })
}

if (require.main === module) main()
