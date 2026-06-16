#!/usr/bin/env tsx
// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { existsSync, statSync, rmSync } from 'fs'
import { join, resolve } from 'path'
import { glob } from 'glob'
import prompts from 'prompts'

const PATTERN_GROUPS = {
  node: ['**/node_modules/**', '**/dist/**', '**/.pnpm-store/**'],
  crates: ['**/target/**', '**/crates/**/tests/fixtures/*.json'],
  contracts: ['**/artifacts/**', '**/cache/**', '**/out/**', '**/broadcast/**', '**/ignition/deployments/**', '**/*contracts/**/types/**'],
  interfoldTemp: ['**/.interfold/data/**', '**/.interfold/config/**', '**/database/**'],
} as const

interface CleanOptions {
  skipNode?: boolean
  skipCrates?: boolean
  skipContracts?: boolean
  interactive?: boolean
  dryRun?: boolean
}

class Cleaner {
  private rootDir: string
  private options: CleanOptions
  private skipPatterns: string[] = []

  constructor(options: CleanOptions = {}) {
    this.rootDir = resolve(__dirname, '..')
    this.options = options
    this.setupSkips()
  }

  private setupSkips(): void {
    // Always skip the following folders.
    this.skipPatterns.push('**/risc0-ethereum/**')
    this.skipPatterns.push('packages/interfold-contracts/artifacts/contracts/**/*.json')
  }

  private getPatterns(): string[] {
    const patterns: string[] = []
    if (!this.options.skipNode) patterns.push(...PATTERN_GROUPS.node)
    if (!this.options.skipCrates) patterns.push(...PATTERN_GROUPS.crates)
    if (!this.options.skipContracts) patterns.push(...PATTERN_GROUPS.contracts)
    // InterfoldTemp is always included.
    patterns.push(...PATTERN_GROUPS.interfoldTemp)
    return patterns
  }

  private getTopLevelPaths(paths: string[]): string[] {
    // Normalize and sort lexicographically
    const sorted = [...paths].map((p) => p.replace(/\\/g, '/')).sort()
    const result: string[] = []
    for (const p of sorted) {
      const last = result[result.length - 1]
      if (!last || !(p === last || p.startsWith(last + '/'))) {
        result.push(p)
      }
    }
    return result
  }

  private async findAll(): Promise<string[]> {
    const patterns = this.getPatterns()
    const matchesPerPattern = await Promise.all(
      patterns.map((pat) =>
        glob(pat, {
          cwd: this.rootDir,
          ignore: ['.git/**', ...this.skipPatterns],
          dot: true,
          nodir: false,
        }),
      ),
    )
    const set = new Set<string>()
    for (const arr of matchesPerPattern) for (const m of arr) set.add(m)
    return [...set].sort()
  }

  private remove(relPath: string, counts: { files: number; dirs: number }): void {
    const full = join(this.rootDir, relPath)
    if (!existsSync(full)) return
    const isDir = statSync(full).isDirectory()
    rmSync(full, { recursive: true, force: true })
    if (isDir) counts.dirs++
    else counts.files++
  }

  async run(): Promise<void> {
    if (this.options.dryRun) {
      console.log('🧹 Cleaning build artifacts (dry run)…\n')
    } else {
      console.log('🧹 Cleaning build artifacts…\n')
    }

    const all = await this.findAll()
    const toClean = all // skip patterns already applied via glob ignore
    const topLevel = this.getTopLevelPaths(toClean)

    if (toClean.length === 0) {
      console.log('✅ Nothing to clean (or everything is skipped).')
      return
    }

    // Optional confirmation
    if (this.options.interactive) {
      console.log(`Found ${toClean.length} paths, ${topLevel.length} top-level to remove.`)
      const { proceed } = await prompts({
        type: 'confirm',
        name: 'proceed',
        message: 'Proceed with deletion?',
        initial: false,
      })
      if (!proceed) {
        console.log('❌ Aborted.')
        return
      }
    }

    const counts = { files: 0, dirs: 0 }
    if (this.options.dryRun) {
      const topLevelPaths = topLevel

      // Sort and print only the top-level directories or files
      topLevelPaths.sort().forEach((p) => console.log(p))

      console.log('\n📝 Dry run complete — no files deleted.')
    } else {
      for (const p of toClean) this.remove(p, counts)

      console.log('\n📊 Summary:')
      console.log(`  Files removed: ${counts.files}`)
      console.log(`  Directories removed: ${counts.dirs}`)
      console.log('\n✅ Done.')
    }
  }
}

function parseArgs(): CleanOptions {
  const args = process.argv.slice(2)
  const opts: CleanOptions = {}

  for (let i = 0; i < args.length; i++) {
    const a = args[i]
    switch (a) {
      case '--skip-node':
        opts.skipNode = true
        break
      case '--skip-crates':
        opts.skipCrates = true
        break
      case '--skip-contracts':
        opts.skipContracts = true
        break
      case '--interactive':
      case '-i':
        opts.interactive = true
        break
      case '--dry-run':
      case '-n':
        opts.dryRun = true
        break
      case '--help':
      case '-h':
        printHelp()
        process.exit(0)
        break
      default:
        if (a.startsWith('-')) {
          console.error(`Unknown option: ${a}`)
          console.error('Use --help for usage information')
          process.exit(1)
        }
    }
  }

  return opts
}

function printHelp(): void {
  console.log(`
🧹 Clean build artifacts

Usage: tsx scripts/clean.ts [options]

Options:
  --skip-node              Skip Node/JS artefacts (node_modules, dist, .pnpm-store)
  --skip-crates            Skip Rust artefacts (target, fixtures)
  --skip-contracts         Skip contract artefacts (artifacts, cache, out, broadcast, ignition, types)
  --interactive, -i        Ask for confirmation before deleting
  --dry-run, -n            List what would be deleted without removing anything
  --help, -h               Show this help

Examples:
  tsx scripts/clean.ts -i
  tsx scripts/clean.ts --skip-node --skip-contracts
`)
}

async function main(): Promise<void> {
  try {
    const opts = parseArgs()
    const cleaner = new Cleaner(opts)
    await cleaner.run()
  } catch (err) {
    console.error('❌ Error:', err)
    process.exit(1)
  }
}

if (require.main === module) {
  main()
}
