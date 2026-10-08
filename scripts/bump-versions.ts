#!/usr/bin/env tsx
// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { readFileSync, writeFileSync, existsSync } from 'fs'
import { join, resolve } from 'path'
import { execFileSync, execSync } from 'child_process'

interface PackageJson {
  name: string
  version: string
}

interface BumpOptions {
  skipGit?: boolean
  skipPush?: boolean
  dryRun?: boolean
}

class VersionBumper {
  private newVersion: string
  private oldVersion: string | null = null
  private rootDir: string
  private options: BumpOptions

  constructor(newVersion: string, options: BumpOptions = {}) {
    this.newVersion = newVersion
    this.rootDir = resolve(__dirname, '..')
    this.options = options
  }

  /**
   * Main entry point to bump all versions
   */
  bumpAll(): void {
    console.log(`🚀 Bumping all versions to ${this.newVersion}`)

    if (this.options.dryRun) {
      console.log('📝 DRY RUN MODE - No changes will be made')
    }

    try {
      // Validate version format
      this.validateVersion(this.newVersion)

      // Get current version from root package.json or Cargo.toml
      this.oldVersion = this.getCurrentVersion()
      console.log(`📌 Current version: ${this.oldVersion || 'unknown'}`)

      if (!this.isPrerelease()) {
        this.validateDappNodeUpstreamProgression()
      }

      // Check for uncommitted changes
      if (!this.options.skipGit && !this.options.dryRun) {
        this.checkReleaseBranch()
        this.checkGitStatus()
      }

      // In dry-run mode, just show what would happen
      if (this.options.dryRun) {
        console.log('\n📋 Would perform the following actions:')
        console.log('   1. Update Rust workspace version in Cargo.toml')
        console.log('   2. Update NPM package versions in:')
        console.log('      - Root package.json')
        console.log('      - packages/interfold-sdk')
        console.log('      - packages/interfold-contracts')
        console.log('      - packages/interfold-config')
        console.log('      - packages/interfold-react')
        console.log('      - packages/interfold-mcp')
        console.log('      - crates/wasm')
        console.log('   3. Pin the ciphernode circuit archive to the release version')
        const dappNodeAction = this.isPrerelease()
          ? 'skip for pre-release'
          : `update upstream image to ${this.newVersion} and bump wrapper version`
        console.log(`   4. DAppNode package: ${dappNodeAction}`)
        console.log('   5. Update lock files (Cargo.lock, pnpm-lock.yaml)')
        console.log('   6. Generate/update CHANGELOG.md')
        if (!this.options.skipGit) {
          console.log('   7. Commit changes')
          if (!this.options.skipPush) {
            console.log('   8. Push the release branch to origin')
          }
        }
        console.log('\n✅ Dry run complete. Run without --dry-run to perform these actions.')
        return
      }

      // Bump Rust crates
      this.bumpRustCrates()

      // Bump npm packages
      this.bumpNpmPackages()

      // The release workflow publishes the archive under this same tag.
      this.bumpCircuitArchiveVersion()

      // Bump DAppNode package for stable releases
      this.bumpDappNodePackage()

      // Update lock files
      this.updateLockFiles()

      // Generate changelog
      this.generateChangelog()

      // Git operations
      if (!this.options.skipGit && !this.options.dryRun) {
        this.performGitOperations()
      }

      console.log('\n✅ All versions bumped successfully!')
      console.log('\n📋 Summary:')
      console.log(`   Previous version: ${this.oldVersion || 'unknown'}`)
      console.log(`   New version: ${this.newVersion}`)
      console.log(`   Rust crates: ✓`)
      console.log(`   NPM packages: ✓`)
      console.log(`   DAppNode package: ${this.isPrerelease() ? 'skipped for pre-release' : '✓'}`)
      console.log(`   Lock files: ✓`)
      console.log(`   Changelog: ✓`)

      if (!this.options.skipGit && !this.options.dryRun) {
        console.log(`   Git commit: ✓`)

        if (!this.options.skipPush) {
          console.log(`   Release branch push: ✓`)
          console.log('\n💡 Next steps:')
          console.log('   1. Open the release pull request and wait for CI')
          console.log('   2. Merge the pull request into main')
          console.log('   3. Update local main')
          console.log(`   4. Run: pnpm release:tag ${this.newVersion}`)
        } else {
          console.log('\n💡 Next steps:')
          console.log('   1. Push this release branch and open a pull request')
          console.log('   2. Wait for CI and merge it into main')
          console.log('   3. Update local main')
          console.log(`   4. Run: pnpm release:tag ${this.newVersion}`)
        }
      } else if (this.options.dryRun) {
        console.log('\n💡 Dry run complete. To perform actual bump, run without --dry-run')
      } else {
        console.log('\n💡 Next steps:')
        console.log('   1. Review the changes and CHANGELOG.md')
        console.log('   2. Commit: git add . && git commit -m "chore(release): bump version to ' + this.newVersion + '"')
        console.log('   3. Push the release branch and merge it after CI passes')
        console.log('   4. Update local main')
        console.log(`   5. Run: pnpm release:tag ${this.newVersion}`)
      }
    } catch (error) {
      console.error('❌ Error bumping versions:', error)
      process.exit(1)
    }
  }

  /**
   * Require a reviewable branch before the script creates its release commit.
   */
  private checkReleaseBranch(): void {
    const currentBranch = execSync('git symbolic-ref --quiet --short HEAD', {
      cwd: this.rootDir,
      encoding: 'utf-8',
    }).trim()

    if (!currentBranch || currentBranch === 'main' || currentBranch === 'dev') {
      throw new Error(`Run the version bump on a release branch, not ${currentBranch || 'a detached commit'}`)
    }
  }

  /**
   * Check git status for uncommitted changes
   */
  private checkGitStatus(): void {
    try {
      const status = execSync('git status --porcelain', {
        cwd: this.rootDir,
        encoding: 'utf-8',
      }).trim()

      if (status) {
        console.error('❌ Error: You have uncommitted changes.')
        console.error('   Please commit or stash your changes before bumping versions.')
        console.error('\n   Uncommitted files:')
        console.error(
          status
            .split('\n')
            .map((line) => '   ' + line)
            .join('\n'),
        )
        console.error('\n   To proceed anyway, use --skip-git flag')
        process.exit(1)
      }
    } catch {
      console.warn('⚠️  Could not check git status')
    }
  }

  /**
   * Commit the release preparation and optionally push its branch.
   */
  private performGitOperations(): void {
    console.log('\n📝 Performing git operations...')

    try {
      // Run prettier from root before committing to avoid hook failures
      console.log('   Running prettier from root...')
      try {
        execSync('pnpm format', {
          cwd: this.rootDir,
          stdio: 'pipe',
        })
        console.log('   ✓ Prettier formatting complete')
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
      } catch (error) {
        console.warn('   ⚠️  Prettier failed, continuing anyway')
      }

      // Add all changes
      console.log('   Adding changes...')
      execSync('git add .', { cwd: this.rootDir })

      // Create commit message
      const commitMessageLines = [
        `chore(release): bump version to ${this.newVersion}`,
        '',
        `- Updated all Rust crates to ${this.newVersion}`,
        `- Updated all npm packages to ${this.newVersion}`,
      ]
      if (!this.isPrerelease()) {
        commitMessageLines.push(`- Updated DAppNode upstream image to ${this.newVersion}`)
      }
      commitMessageLines.push('- Updated lock files', '- Generated CHANGELOG.md')
      const commitMessage = commitMessageLines.join('\n')

      // Commit changes
      console.log('   Committing changes...')
      execSync(`git commit -m "${commitMessage}"`, {
        cwd: this.rootDir,
        stdio: 'pipe',
      })
      console.log(`   ✓ Committed with message: "chore(release): bump version to ${this.newVersion}"`)

      // Push the release branch unless --no-push was specified. A separate command creates the
      // release tag from updated main after this commit passes pull-request CI and is merged.
      if (!this.options.skipPush) {
        console.log('   Pushing to remote...')

        // Push commits
        const currentBranch = execSync('git rev-parse --abbrev-ref HEAD', {
          cwd: this.rootDir,
          encoding: 'utf8',
        }).trim()

        execSync(`git push origin ${currentBranch}`, {
          cwd: this.rootDir,
          stdio: 'pipe',
        })
        console.log(`   ✓ Pushed commits to ${currentBranch}`)
      }
    } catch (error: any) {
      console.error('❌ Error during git operations:', error.message)
      throw error
    }
  }

  /**
   * Get current version from the monorepo
   */
  private getCurrentVersion(): string | null {
    // Try to get from root package.json first
    const rootPackagePath = join(this.rootDir, 'package.json')
    if (existsSync(rootPackagePath)) {
      const content = readFileSync(rootPackagePath, 'utf-8')
      const packageJson = JSON.parse(content)
      if (packageJson.version) {
        return packageJson.version
      }
    }

    // Try to get from root Cargo.toml workspace version
    const rootCargoPath = join(this.rootDir, 'Cargo.toml')
    if (existsSync(rootCargoPath)) {
      const content = readFileSync(rootCargoPath, 'utf-8')
      const versionMatch = content.match(/\[workspace\.package\][\s\S]*?version = "([^"]+)"/)
      if (versionMatch) {
        return versionMatch[1]
      }
    }

    return null
  }

  /**
   * Generate changelog using conventional commits
   */
  private generateChangelog(): void {
    console.log('\n📝 Generating changelog...')

    // The version tag is created after this release branch merges. Assign the
    // untagged commits to the new version now so that the release notes are not
    // one version behind. The checked-in config also excludes release-bump
    // commits, including the previous release PR merge that occurs after its tag.
    execFileSync(
      'pnpm',
      ['auto-changelog', '--config', '.auto-changelog', '--output', 'CHANGELOG.md', '--latest-version', `v${this.newVersion}`],
      {
        cwd: this.rootDir,
        stdio: 'inherit',
      },
    )

    console.log('   ✓ Changelog generated successfully')
  }

  /**
   * Update lock files after version bump
   */
  private updateLockFiles(): void {
    console.log('\n🔒 Updating lock files...')

    // Each Cargo workspace whose lock file records the versions of the Interfold crates. The OpenVM
    // guests are separate workspaces. A `--locked` guest build fails when their lock files are stale.
    const cargoWorkspaces = ['.', 'examples/CRISP', 'examples/CRISP/guest', 'templates/default', 'templates/default/guest']
    const failedWorkspaces: string[] = []
    for (const workspace of cargoWorkspaces) {
      try {
        execSync('cargo update --workspace', {
          cwd: join(this.rootDir, workspace),
          stdio: 'pipe',
        })
      } catch (error) {
        const stderr = error instanceof Error && 'stderr' in error && error.stderr != null ? String(error.stderr).trim() : ''
        console.error(`   ✗ Could not update ${workspace}/Cargo.lock${stderr ? `: ${stderr}` : ''}`)
        failedWorkspaces.push(workspace)
      }
    }
    if (failedWorkspaces.length > 0) {
      throw new Error(`Could not update the Cargo.lock of: ${failedWorkspaces.join(', ')}`)
    }
    console.log('   ✓ Cargo.lock updated')

    // Detect and update the appropriate Node.js lock file
    const pnpmLockPath = join(this.rootDir, 'pnpm-lock.yaml')

    if (existsSync(pnpmLockPath)) {
      try {
        execSync('pnpm install --lockfile-only', {
          cwd: this.rootDir,
          stdio: 'pipe',
        })
        console.log('   ✓ pnpm-lock.yaml updated')
      } catch {
        console.warn('   ⚠️  Could not update pnpm-lock.yaml')
      }
    }
  }

  /**
   * Validate version format (semantic versioning)
   */
  private validateVersion(version: string): void {
    const semverRegex = /^\d+\.\d+\.\d+(-[a-zA-Z0-9.-]+)?(\+[a-zA-Z0-9.-]+)?$/
    if (!semverRegex.test(version)) {
      throw new Error(`Invalid version format: ${version}. Expected format: x.y.z[-prerelease][+build]`)
    }
  }

  /**
   * Bump versions in all Rust crates
   */
  private bumpRustCrates(): void {
    console.log('\n🦀 Bumping Rust crate versions...')

    // Update root Cargo.toml workspace version (this propagates to all crates)
    const rootCargoPath = join(this.rootDir, 'Cargo.toml')
    this.updateCargoToml(rootCargoPath)

    // Update workspace dependencies in root Cargo.toml
    this.updateWorkspaceDependencies(rootCargoPath)

    console.log('   ✓ All workspace crates updated via workspace.version')
  }

  /**
   * Bump versions in all npm packages
   */
  private bumpNpmPackages(): void {
    console.log('\n📦 Bumping NPM package versions...')

    // Update root package.json if it exists
    const rootPackagePath = join(this.rootDir, 'package.json')
    this.updatePackageJson(rootPackagePath)
    console.log('   ✓ Root package.json')

    // Main packages to bump (excluding examples and templates)
    const packagesToBump = [
      'packages/interfold-sdk',
      'packages/interfold-contracts',
      'packages/interfold-config',
      'packages/interfold-react',
      'packages/interfold-mcp',
      'crates/wasm',
    ]

    for (const packagePath of packagesToBump) {
      const fullPath = join(this.rootDir, packagePath)
      const packageJsonPath = join(fullPath, 'package.json')

      this.updatePackageJson(packageJsonPath)
      const packageName = this.getPackageName(packageJsonPath)
      console.log(`   ✓ ${packageName}`)
    }
  }

  /**
   * Pin the circuit archive downloaded by this ciphernode release.
   */
  private bumpCircuitArchiveVersion(): void {
    const versionsPath = join(this.rootDir, 'crates/zk-prover/versions.json')
    const versions = JSON.parse(readFileSync(versionsPath, 'utf-8'))
    versions.required_circuits_version = this.newVersion
    writeFileSync(versionsPath, JSON.stringify(versions, null, 2) + '\n')
    console.log(`   ✓ Circuit archive pinned to ${this.newVersion}`)
  }

  /**
   * Bump the DAppNode wrapper when publishing a stable ciphernode image.
   */
  private bumpDappNodePackage(): void {
    console.log('\n🧩 Bumping DAppNode package version...')

    if (this.isPrerelease()) {
      console.log('   Skipping DAppNode package for pre-release tag')
      return
    }

    const packagePath = join(this.rootDir, 'dappnode/dappnode_package.json')
    const packageJson = JSON.parse(readFileSync(packagePath, 'utf-8'))
    const dappNodeVersion = this.nextDappNodeWrapperVersion(packageJson.version, packageJson.upstreamVersion, this.newVersion)

    packageJson.version = dappNodeVersion
    packageJson.upstreamVersion = this.newVersion
    writeFileSync(packagePath, JSON.stringify(packageJson, null, 2) + '\n')
    console.log('   ✓ dappnode_package.json')

    this.updateDappNodeNpmVersion(dappNodeVersion)

    this.replaceInFile(join(this.rootDir, 'dappnode/docker-compose.yml'), [
      [/UPSTREAM_VERSION: [^\n]+/, `UPSTREAM_VERSION: ${this.newVersion}`],
      [
        /image: 'ciphernode\.interfold-ciphernode\.public\.dappnode\.eth:[^']+'/,
        `image: 'ciphernode.interfold-ciphernode.public.dappnode.eth:${dappNodeVersion}'`,
      ],
    ])
    console.log('   ✓ docker-compose.yml')

    this.replaceInFile(join(this.rootDir, 'dappnode/Dockerfile'), [
      [/ARG UPSTREAM_VERSION=[^\n]+/, `ARG UPSTREAM_VERSION=${this.newVersion}`],
    ])
    console.log('   ✓ Dockerfile')
    console.log(`   ✓ wrapper ${dappNodeVersion} uses upstream ${this.newVersion}`)
  }

  private updateDappNodeNpmVersion(dappNodeVersion: string): void {
    const npmPackagePath = join(this.rootDir, 'dappnode/package.json')
    const npmPackageJson = JSON.parse(readFileSync(npmPackagePath, 'utf-8'))
    npmPackageJson.version = dappNodeVersion
    writeFileSync(npmPackagePath, JSON.stringify(npmPackageJson, null, 2) + '\n')

    const lockPath = join(this.rootDir, 'dappnode/package-lock.json')
    const lockJson = JSON.parse(readFileSync(lockPath, 'utf-8'))
    lockJson.version = dappNodeVersion
    if (lockJson.packages?.['']) {
      lockJson.packages[''].version = dappNodeVersion
    }
    writeFileSync(lockPath, JSON.stringify(lockJson, null, 2) + '\n')
    console.log('   ✓ dappnode npm package metadata')
  }

  private nextDappNodeWrapperVersion(currentWrapperVersion: string, previousUpstreamVersion: string, nextUpstreamVersion: string): string {
    const currentWrapper = this.parseSemverCore(currentWrapperVersion)
    const previousUpstream = this.parseSemverCore(previousUpstreamVersion)
    const nextUpstream = this.parseSemverCore(nextUpstreamVersion)

    if (this.semverCoreLessThan(nextUpstream, previousUpstream)) {
      throw new Error(`Upstream version cannot decrease: ${previousUpstreamVersion} -> ${nextUpstreamVersion}`)
    }

    if (nextUpstream.major !== previousUpstream.major) {
      return `${currentWrapper.major + 1}.0.0`
    }
    if (nextUpstream.minor !== previousUpstream.minor) {
      return `${currentWrapper.major}.${currentWrapper.minor + 1}.0`
    }
    return `${currentWrapper.major}.${currentWrapper.minor}.${currentWrapper.patch + 1}`
  }

  private validateDappNodeUpstreamProgression(): void {
    const packagePath = join(this.rootDir, 'dappnode/dappnode_package.json')
    const packageJson = JSON.parse(readFileSync(packagePath, 'utf-8'))
    const previousUpstream = this.parseSemverCore(packageJson.upstreamVersion)
    const nextUpstream = this.parseSemverCore(this.newVersion)

    if (this.semverCoreLessThan(nextUpstream, previousUpstream)) {
      throw new Error(`Upstream version cannot decrease: ${packageJson.upstreamVersion} -> ${this.newVersion}`)
    }
  }

  private parseSemverCore(version: string): { major: number; minor: number; patch: number } {
    const match = version.match(/^(\d+)\.(\d+)\.(\d+)/)
    if (!match) {
      throw new Error(`Invalid version format: ${version}`)
    }
    return {
      major: Number(match[1]),
      minor: Number(match[2]),
      patch: Number(match[3]),
    }
  }

  private semverCoreLessThan(
    left: { major: number; minor: number; patch: number },
    right: { major: number; minor: number; patch: number },
  ): boolean {
    if (left.major !== right.major) {
      return left.major < right.major
    }
    if (left.minor !== right.minor) {
      return left.minor < right.minor
    }
    return left.patch < right.patch
  }

  private replaceInFile(filePath: string, replacements: [RegExp, string][]): void {
    let content = readFileSync(filePath, 'utf-8')
    for (const [pattern, replacement] of replacements) {
      if (!pattern.test(content)) {
        throw new Error(`Could not find pattern ${pattern} in ${filePath}`)
      }
      content = content.replace(pattern, replacement)
    }
    writeFileSync(filePath, content)
  }

  private isPrerelease(): boolean {
    return this.newVersion.includes('-')
  }

  /**
   * Update Cargo.toml file (workspace version and dependencies)
   */
  private updateCargoToml(filePath: string): void {
    const content = readFileSync(filePath, 'utf-8')
    const lines = content.split('\n')

    let updated = false

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim()

      // Update workspace package version
      if (line === '[workspace.package]') {
        // Look for version in the next few lines
        for (let j = i + 1; j < Math.min(i + 10, lines.length); j++) {
          if (lines[j].trim().startsWith('version = ')) {
            lines[j] = `version = "${this.newVersion}"`
            updated = true
            break
          }
        }
      }

      // Update workspace dependencies
      if (line === '[workspace.dependencies]') {
        // Look for dependency lines with inline versions
        for (let j = i + 1; j < lines.length; j++) {
          const depLine = lines[j].trim()

          // Skip empty lines and new sections
          if (depLine === '' || depLine.startsWith('[')) {
            break
          }

          // Update lines that have version = "..." in them
          if (depLine.includes('version = ')) {
            // Replace the version part while preserving the rest
            const updatedLine = depLine.replace(/version = "[^"]*"/, `version = "${this.newVersion}"`)
            lines[j] = updatedLine
            updated = true
          }
        }
      }
    }

    if (updated) {
      writeFileSync(filePath, lines.join('\n'))
    } else {
      console.warn(`⚠️  Could not find version in ${filePath}`)
    }
  }

  /**
   * Update workspace dependencies in root Cargo.toml
   */
  private updateWorkspaceDependencies(filePath: string): void {
    const content = readFileSync(filePath, 'utf-8')
    const lines = content.split('\n')

    let inWorkspaceDeps = false
    let updated = false

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim()

      if (line === '[workspace.dependencies]') {
        inWorkspaceDeps = true
        continue
      }

      if (inWorkspaceDeps && line.startsWith('version = ')) {
        lines[i] = `version = "${this.newVersion}"`
        updated = true
      }

      // Reset when we hit a new section
      if (line.startsWith('[') && inWorkspaceDeps && line !== '[workspace.dependencies]') {
        break
      }
    }

    if (updated) {
      writeFileSync(filePath, lines.join('\n'))
    }
  }

  /**
   * Update package.json file
   */
  private updatePackageJson(filePath: string): void {
    const content = readFileSync(filePath, 'utf-8')
    const packageJson: PackageJson = JSON.parse(content)

    packageJson.version = this.newVersion

    // Write back with proper formatting
    writeFileSync(filePath, JSON.stringify(packageJson, null, 2) + '\n')
  }

  /**
   * Get package name from package.json
   */
  private getPackageName(filePath: string): string {
    const content = readFileSync(filePath, 'utf-8')
    const packageJson: PackageJson = JSON.parse(content)
    return packageJson.name
  }
}

// CLI interface
function main() {
  const args = process.argv.slice(2)

  // Parse options
  const options: BumpOptions = {}
  let version: string | null = null

  for (let i = 0; i < args.length; i++) {
    const arg = args[i]

    if (arg === '--help' || arg === '-h') {
      showHelp()
      process.exit(0)
    } else if (arg === '--skip-git') {
      options.skipGit = true
    } else if (arg === '--no-push') {
      options.skipPush = true
    } else if (arg === '--dry-run') {
      options.dryRun = true
    } else if (!arg.startsWith('-')) {
      version = arg
    }
  }

  if (!version) {
    console.error('❌ Error: Version is required')
    showHelp()
    process.exit(1)
  }

  const bumper = new VersionBumper(version, options)
  bumper.bumpAll()
}

function showHelp() {
  console.log(`
Usage: pnpm bump:versions [options] <version>

Version Bump Script for Interfold Monorepo
Bumps all versions, generates the changelog, commits, and pushes the release branch.

Arguments:
  version             The new version (e.g., 1.0.0, 1.0.0-beta.1)

Options:
  --skip-git          Skip all git operations (add, commit, push)
  --no-push           Commit locally but do not push the release branch
  --dry-run           Show what would be done without making changes
  --help, -h          Show this help message

Examples:
  # Prepare and push a release branch
  tsx scripts/bump-versions.ts 1.0.0

  # Pre-release
  tsx scripts/bump-versions.ts 1.0.0-beta.1

  # Prepare and commit locally
  tsx scripts/bump-versions.ts --no-push 1.0.0

  # Manual git operations
  tsx scripts/bump-versions.ts --skip-git 1.0.0

  # Test what would happen
  tsx scripts/bump-versions.ts --dry-run 1.0.0

The script will:
  1. Check for uncommitted changes
  2. Update versions in all Rust crates and npm packages
  3. Update lock files (Cargo.lock, pnpm-lock.yaml)
  4. Generate/update CHANGELOG.md
  5. Commit changes with message: "chore(release): bump version to X.Y.Z"
  6. Push the release branch

After CI passes and the release pull request is merged, update main and run
\`pnpm release:tag X.Y.Z\`. That command tags only the protected main commit. The release workflow
runs the complete CI suite for the tagged commit before it publishes any release output.
`)
}

// Run if called directly
if (require.main === module) {
  main()
}

export { VersionBumper }
