#!/usr/bin/env tsx
// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { readFileSync, writeFileSync, existsSync } from 'fs'
import { join, resolve } from 'path'
import { execSync } from 'child_process'

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

      // Check for uncommitted changes
      if (!this.options.skipGit && !this.options.dryRun) {
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
        console.log('      - crates/wasm')
        console.log('   3. Update lock files (Cargo.lock, pnpm-lock.yaml)')
        console.log('   4. Generate/update CHANGELOG.md')
        if (!this.options.skipGit) {
          console.log('   5. Commit changes')
          console.log(`   6. Create tag: v${this.newVersion}`)
          if (!this.options.skipPush) {
            console.log('   7. Push commits and tag to origin')
          }
        }
        console.log('\n✅ Dry run complete. Run without --dry-run to perform these actions.')
        return
      }

      // Bump Rust crates
      this.bumpRustCrates()

      // Bump npm packages
      this.bumpNpmPackages()

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
      console.log(`   Lock files: ✓`)
      console.log(`   Changelog: ✓`)

      if (!this.options.skipGit && !this.options.dryRun) {
        console.log(`   Git commit: ✓`)
        console.log(`   Git tag: v${this.newVersion} ✓`)

        if (!this.options.skipPush) {
          console.log(`   Git push: ✓`)
          console.log(`   Tag push: ✓`)
          console.log('\n🎉 Release tag pushed! The release workflow will start automatically.')
        } else {
          console.log('\n💡 Next steps:')
          console.log('   Push changes and tag to trigger release:')
          console.log('   git push && git push --tags')
        }
      } else if (this.options.dryRun) {
        console.log('\n💡 Dry run complete. To perform actual bump, run without --dry-run')
      } else {
        console.log('\n💡 Next steps:')
        console.log('   1. Review the changes and CHANGELOG.md')
        console.log('   2. Commit: git add . && git commit -m "chore(release): bump version to ' + this.newVersion + '"')
        console.log('   3. Tag: git tag v' + this.newVersion)
        console.log('   4. Push: git push && git push --tags')
      }
    } catch (error) {
      console.error('❌ Error bumping versions:', error)
      process.exit(1)
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
   * Perform git operations (add, commit, tag, push)
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
      const commitMessage = `chore(release): bump version to ${this.newVersion}
  
  - Updated all Rust crates to ${this.newVersion}
  - Updated all npm packages to ${this.newVersion}
  - Updated lock files
  - Generated CHANGELOG.md`

      // Commit changes
      console.log('   Committing changes...')
      execSync(`git commit -m "${commitMessage}"`, {
        cwd: this.rootDir,
        stdio: 'pipe',
      })
      console.log(`   ✓ Committed with message: "chore(release): bump version to ${this.newVersion}"`)

      // Create tag
      const tagName = `v${this.newVersion}`
      console.log(`   Creating tag ${tagName}...`)

      // Check if it's a pre-release
      const isPrerelease = this.newVersion.includes('-')
      const tagMessage = isPrerelease ? `Pre-release ${this.newVersion}` : `Release ${this.newVersion}`

      execSync(`git tag -a ${tagName} -m "${tagMessage}"`, {
        cwd: this.rootDir,
        stdio: 'pipe',
      })
      console.log(`   ✓ Created tag: ${tagName}`)

      // Push changes and tag (unless --no-push was specified)
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

        // Push tag
        execSync(`git push origin ${tagName}`, {
          cwd: this.rootDir,
          stdio: 'pipe',
        })
        console.log(`   ✓ Pushed tag ${tagName}`)
      }
    } catch (error: any) {
      console.error('❌ Error during git operations:', error.message)
      console.error('\n💡 If the tag already exists, delete it first:')
      console.error(`   git tag -d v${this.newVersion}`)
      console.error(`   git push --delete origin v${this.newVersion}`)
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

    try {
      execSync('pnpm auto-changelog --help', {
        stdio: 'ignore',
        cwd: this.rootDir,
      })

      console.log('\n📝 Generating changelog...')
      try {
        execSync('pnpm auto-changelog -o CHANGELOG.md --commit-limit false --tag-prefix v', {
          cwd: this.rootDir,
          stdio: 'inherit',
        })
        console.log('   ✓ Changelog generated successfully')
      } catch (error) {
        console.warn('   ⚠️  Could not generate changelog:', error)
      }

      console.log('   ✓ Changelog generated successfully')
    } catch (error) {
      console.warn('   ⚠️  Could not generate changelog:', error)
      console.log('   Continuing without changelog...')
    }
  }

  /**
   * Update lock files after version bump
   */
  private updateLockFiles(): void {
    console.log('\n🔒 Updating lock files...')

    // Update Cargo.lock
    try {
      execSync('cargo update --workspace', {
        cwd: this.rootDir,
        stdio: 'pipe',
      })
      execSync('cargo update --workspace', {
        cwd: `${this.rootDir}/examples/CRISP`,
        stdio: 'pipe',
      })
      execSync('cargo update --workspace', {
        cwd: `${this.rootDir}/templates/default`,
        stdio: 'pipe',
      })
      console.log('   ✓ Cargo.lock updated')
    } catch {
      console.warn('   ⚠️  Could not update Cargo.lock')
    }

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
Bumps all versions, generates changelog, commits, tags, and pushes to trigger release.

Arguments:
  version             The new version (e.g., 1.0.0, 1.0.0-beta.1)

Options:
  --skip-git          Skip all git operations (add, commit, tag, push)
  --no-push           Perform git operations but don't push (local only)
  --dry-run           Show what would be done without making changes
  --help, -h          Show this help message

Examples:
  # Full release (bump, commit, tag, push)
  tsx scripts/bump-versions.ts 1.0.0

  # Pre-release
  tsx scripts/bump-versions.ts 1.0.0-beta.1

  # Local only (don't push)
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
  6. Create annotated tag: vX.Y.Z
  7. Push commits and tag to trigger the release workflow

Note: Pushing the tag will automatically trigger the GitHub Actions release workflow.
`)
}

// Run if called directly
if (require.main === module) {
  main()
}

export { VersionBumper }
