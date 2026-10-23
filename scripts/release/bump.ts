#!/usr/bin/env tsx
// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'

import { bumpDappnodeVersions, dappnodeVersionFiles } from './dappnode.mjs'
import { CARGO_WORKSPACES, PACKAGE_FILES, normalizeVersion, releaseChannel } from './version.mjs'

export interface BumpOptions {
  commit?: boolean
  push?: boolean
  dryRun?: boolean
}

type Execute = (command: string, args: string[], cwd: string) => string
const executeCommand: Execute = (command, args, cwd) =>
  execFileSync(command, args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] })

/** Change only the workspace package and local path dependencies, never registry pins. */
export function bumpCargoManifest(content: string, version: string): string {
  let section = ''
  let foundVersion = false
  const result = content
    .split('\n')
    .map((line) => {
      if (/^\s*\[/.test(line)) section = line.trim()
      if (section === '[workspace.package]' && /^version\s*=/.test(line)) {
        foundVersion = true
        return line.replace(/"[^"]*"/, `"${version}"`)
      }
      if (section === '[workspace.dependencies]' && /\bpath\s*=\s*"/.test(line))
        return line.replace(/\bversion\s*=\s*"[^"]*"/, `version = "${version}"`)
      return line
    })
    .join('\n')
  if (!foundVersion) throw new Error('Cargo.toml does not contain workspace.package.version')
  return result
}

function core(version: string): number[] {
  return normalizeVersion(version).split(/[+-]/)[0].split('.').map(Number)
}

function nextWrapperVersion(wrapper: string, previous: string, next: string): string {
  const oldCore = core(previous)
  const newCore = core(next)
  const difference = newCore.findIndex((part, index) => part !== oldCore[index])
  if (difference !== -1 && newCore[difference] < oldCore[difference])
    throw new Error(`Upstream version cannot decrease: ${previous} -> ${next}`)
  const result = core(wrapper)
  const bump = difference === -1 ? 2 : difference
  result[bump]++
  for (let i = bump + 1; i < result.length; i++) result[i] = 0
  return result.join('.')
}

export class VersionBumper {
  private readonly newVersion: string
  private readonly rootDir: string
  private readonly execute: Execute

  constructor(
    version: string,
    private readonly options: BumpOptions = {},
    dependencies: { rootDir?: string; execute?: Execute } = {},
  ) {
    this.newVersion = normalizeVersion(version)
    this.rootDir = dependencies.rootDir ?? resolve(__dirname, '../..')
    this.execute = dependencies.execute ?? executeCommand
  }

  private read(path: string): string {
    return readFileSync(join(this.rootDir, path), 'utf8')
  }
  private write(path: string, content: string): void {
    writeFileSync(join(this.rootDir, path), content)
  }
  private json(path: string): any {
    return JSON.parse(this.read(path))
  }
  private writeJson(path: string, value: unknown): void {
    this.write(path, JSON.stringify(value, null, 2) + '\n')
  }
  private run(command: string, args: string[], workspace = '.'): string {
    return this.execute(command, args, join(this.rootDir, workspace))
  }

  bumpAll(): void {
    if (this.options.push && !this.options.commit) throw new Error('--push requires --commit')
    const stable = releaseChannel(this.newVersion) === 'latest'
    const previous = this.json('package.json').version
    const cargo = bumpCargoManifest(this.read('Cargo.toml'), this.newVersion)
    const dappnode = stable ? this.json('dappnode/dappnode_package.json') : undefined
    const wrapperVersion = stable ? nextWrapperVersion(dappnode.version, dappnode.upstreamVersion, this.newVersion) : undefined
    const outputs = [
      'Cargo.toml',
      ...PACKAGE_FILES,
      'crates/zk/prover/versions.json',
      ...CARGO_WORKSPACES.map((workspace: string) => join(workspace, 'Cargo.lock')),
      'pnpm-lock.yaml',
      'CHANGELOG.md',
      ...(stable ? dappnodeVersionFiles(this.rootDir) : []),
    ]
    if (this.options.dryRun) {
      console.log(
        `Would prepare ${previous} -> ${this.newVersion}:\n${outputs.join('\n')}\nUpdate locks, changelog, and format changed release files.`,
      )
      console.log(`Commit: ${Boolean(this.options.commit)}; push: ${Boolean(this.options.push)}. No writes or commands executed.`)
      return
    }

    let branch = ''
    if (this.options.commit) {
      branch = this.run('git', ['symbolic-ref', '--quiet', '--short', 'HEAD']).trim()
      if (!branch || branch === 'main' || branch === 'dev')
        throw new Error(`Run the version bump on a release branch, not ${branch || 'a detached commit'}`)
      if (this.run('git', ['status', '--porcelain']).trim())
        throw new Error('Commit mode requires a clean index and working tree. Prepare without --commit to review files manually.')
    }

    const before = new Map(outputs.map((path) => [path, existsSync(join(this.rootDir, path)) ? this.read(path) : null]))
    this.write('Cargo.toml', cargo)
    for (const path of PACKAGE_FILES) this.writeJson(path, { ...this.json(path), version: this.newVersion })
    const versions = this.json('crates/zk/prover/versions.json')
    this.writeJson('crates/zk/prover/versions.json', { ...versions, required_circuits_version: this.newVersion })
    if (stable) bumpDappnodeVersions(this.rootDir, this.newVersion, wrapperVersion!)

    // Each required command must succeed before any stage/commit/push. Failures leave reviewable
    // preparation files, not a published partial release. Do not silently restore user files.
    for (const workspace of CARGO_WORKSPACES) this.run('cargo', ['update', '--workspace'], workspace)
    this.run('pnpm', ['install', '--lockfile-only'])
    this.run('pnpm', [
      'auto-changelog',
      '--config',
      '.auto-changelog',
      '--output',
      'CHANGELOG.md',
      '--latest-version',
      `v${this.newVersion}`,
    ])
    const changed = outputs.filter((path) => /\.(json|ya?ml|md)$/.test(path) && before.get(path) !== this.read(path))
    if (changed.length) this.run('pnpm', ['exec', 'prettier', '--write', '--', ...changed])

    if (this.options.commit) {
      this.run('git', ['add', '--', ...outputs])
      this.run('git', ['commit', '-m', `chore(release): bump version to ${this.newVersion}`])
      if (this.options.push) this.run('git', ['push', 'origin', branch])
    }
    console.log(`Prepared ${previous} -> ${this.newVersion}. Commit: ${Boolean(this.options.commit)}; push: ${Boolean(this.options.push)}.`)
    console.log(
      'Review release files and CHANGELOG.md. After release-PR CI and merge, update main before pnpm release:tag. See RELEASING.md.',
    )
  }
}

export function main(args = process.argv.slice(2)): void {
  if (args.includes('--help') || args.includes('-h')) {
    console.log(`Usage: pnpm bump:versions <version> [--dry-run] [--commit [--push]]
Default: prepare versions, circuit pin, locks, changelog and format release files only.
--dry-run  Read-only preview; no commands executed
--commit   Require a clean release branch, stage release outputs only and commit
--push     Push that branch to origin; requires --commit
No mode creates tags, opens PRs or publishes packages.
Old --skip-git is now the default; replace --no-push with --commit.
See RELEASING.md for review, tagging and publication.`)
    return
  }
  const options: BumpOptions = {}
  let version: string | undefined
  for (const arg of args) {
    if (arg === '--dry-run') options.dryRun = true
    else if (arg === '--commit') options.commit = true
    else if (arg === '--push') options.push = true
    else if (arg.startsWith('-')) throw new Error(`Unknown option: ${arg}. Use --help for current flags.`)
    else if (version) throw new Error('Expected exactly one version')
    else version = arg
  }
  if (!version) throw new Error('Version is required. Use --help for usage.')
  new VersionBumper(version, options).bumpAll()
}

if (require.main === module) {
  try {
    main()
  } catch (error) {
    console.error(error)
    process.exitCode = 1
  }
}
