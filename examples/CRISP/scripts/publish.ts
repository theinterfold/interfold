#!/usr/bin/env tsx
// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { readFileSync, writeFileSync, existsSync } from 'fs'
import { join, resolve, dirname } from 'path'
import { execSync } from 'child_process'
import { fileURLToPath } from 'url'

// Get __dirname equivalent in ES modules
const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

interface PackageJson {
  name: string
  version: string
}

interface PublishOptions {
  skipGit?: boolean
  dryRun?: boolean
  tag?: string // npm dist-tag (e.g., 'latest', 'beta', 'next')
  noVerify?: boolean
}

class CRISPPublisher {
  private newVersion: string
  private oldVersion: string | null = null
  private crispDir: string
  private options: PublishOptions

  constructor(newVersion: string, options: PublishOptions = {}) {
    this.newVersion = newVersion
    this.crispDir = resolve(__dirname, '..')
    this.options = options
  }

  /**
   * Main entry point to bump versions and publish packages
   */
  async publishAll(): Promise<void> {
    console.log(`🚀 Publishing CRISP packages version ${this.newVersion}`)

    if (this.options.dryRun) {
      console.log('📝 DRY RUN MODE - No changes will be made')
    }

    try {
      // Validate version format
      this.validateVersion(this.newVersion)

      // Get current version
      this.oldVersion = this.getCurrentVersion()
      console.log(`📌 Current version: ${this.oldVersion || 'unknown'}`)

      // Check for uncommitted changes
      if (!this.options.skipGit && !this.options.dryRun) {
        this.checkGitStatus()
      }

      // In dry-run mode, just show what would happen
      if (this.options.dryRun) {
        console.log('\n📋 Would perform the following actions:')
        console.log('   1. Update package versions in:')
        console.log('      - @crisp-e3/sdk')
        console.log('      - @crisp-e3/contracts')
        console.log('      - @crisp-e3/zk-inputs')
        console.log('   2. Update @crisp-e3/sdk dependency in client/package.json')
        console.log('   3. Update pnpm-lock.yaml')
        console.log('   4. Build packages')
        console.log('   5. Publish to npm:')
        console.log('      - @crisp-e3/sdk')
        console.log('      - @crisp-e3/contracts')
        console.log('      - @crisp-e3/zk-inputs')
        console.log('   6. Update the standalone client/pnpm-lock.yaml')
        if (!this.options.skipGit) {
          console.log('   7. Commit changes')
        }
        console.log('\n✅ Dry run complete. Run without --dry-run to perform these actions.')
        return
      }

      // Bump npm packages
      this.bumpNpmPackages()

      // Update client dependency
      this.updateClientDependency()

      // Update lock files
      this.updateLockFiles()

      // Build packages
      await this.buildPackages()

      // Publish packages
      await this.publishPackages()

      // Update the client lock file, which resolves the packages from npm
      await this.updateClientLockFile()

      // Git operations (just commit, no tagging)
      if (!this.options.skipGit && !this.options.dryRun) {
        this.performGitOperations()
      }

      console.log('\n✅ CRISP packages published successfully!')
      console.log('\n📋 Summary:')
      console.log(`   Previous version: ${this.oldVersion || 'unknown'}`)
      console.log(`   New version: ${this.newVersion}`)
      console.log(`   Packages updated: ✓`)
      console.log(`   Client dependency updated: ✓`)
      console.log(`   Packages built: ✓`)
      console.log(`   Packages published: ✓`)

      if (!this.options.skipGit && !this.options.dryRun) {
        console.log(`   Git commit: ✓`)
        console.log('\n💡 Changes committed. Push when ready:')
        console.log('   git push')
      } else if (this.options.dryRun) {
        console.log('\n💡 Dry run complete. To perform actual publish, run without --dry-run')
      } else {
        console.log('\n💡 Next steps:')
        console.log('   1. Review the changes')
        console.log('   2. Commit: git add . && git commit -m "chore(crisp): publish version ' + this.newVersion + '"')
        console.log('   3. Push: git push')
      }

      console.log('\n🎉 Packages are now available on npm!')
      console.log('   npm install @crisp-e3/sdk@' + this.newVersion)
      console.log('   npm install @crisp-e3/contracts@' + this.newVersion)
      console.log('   npm install @crisp-e3/zk-inputs@' + this.newVersion)
    } catch (error) {
      console.error('❌ Error during publish:', error)
      process.exit(1)
    }
  }

  /**
   * Build all packages
   */
  private async buildPackages(): Promise<void> {
    console.log('\n🔨 Building packages...')

    const packagesToBuild = [
      { path: 'packages/crisp-sdk', name: '@crisp-e3/sdk' },
      { path: 'packages/crisp-contracts', name: '@crisp-e3/contracts' },
      { path: 'packages/crisp-zk-inputs', name: '@crisp-e3/zk-inputs' },
    ]

    for (const pkg of packagesToBuild) {
      try {
        const pkgPath = join(this.crispDir, pkg.path)

        console.log(`   Building ${pkg.name}...`)

        // Check if package has a build script
        const packageJsonPath = join(pkgPath, 'package.json')
        const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf-8'))

        if (packageJson.scripts && packageJson.scripts.build) {
          execSync('pnpm build', {
            cwd: pkgPath,
            stdio: 'inherit',
          })
          console.log(`   ✓ ${pkg.name} built successfully`)
        } else {
          console.log(`   ⚠️  ${pkg.name} has no build script, skipping`)
        }
      } catch (error) {
        console.error(`   ❌ Failed to build ${pkg.name}`)
        throw error
      }
    }
  }

  /**
   * Publish all packages to npm
   */
  private async publishPackages(): Promise<void> {
    console.log('\n📤 Publishing packages to npm...')

    const packagesToPublish = [
      { path: 'packages/crisp-sdk', name: '@crisp-e3/sdk' },
      { path: 'packages/crisp-contracts', name: '@crisp-e3/contracts' },
      { path: 'packages/crisp-zk-inputs', name: '@crisp-e3/zk-inputs' },
    ]

    const tag = this.options.tag || (this.newVersion.includes('-') ? 'next' : 'latest')
    console.log(`   Using npm tag: ${tag}`)

    for (const pkg of packagesToPublish) {
      try {
        const pkgPath = join(this.crispDir, pkg.path)

        console.log(`   Publishing ${pkg.name}...`)

        execSync(`pnpm publish --access public --tag ${tag} --no-git-checks`, {
          cwd: pkgPath,
          stdio: 'inherit',
        })

        console.log(`   ✓ ${pkg.name}@${this.newVersion} published successfully`)
      } catch (error) {
        console.error(`   ❌ Failed to publish ${pkg.name}`)
        throw error
      }
    }
  }

  /**
   * Check git status for uncommitted changes
   */
  private checkGitStatus(): void {
    try {
      const status = execSync('git status --porcelain', {
        cwd: this.crispDir,
        encoding: 'utf-8',
      }).trim()

      if (status) {
        console.error('❌ Error: You have uncommitted changes.')
        console.error('   Please commit or stash your changes before publishing.')
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
   * Perform git operations (add and commit only, no tagging)
   */
  private performGitOperations(): void {
    console.log('\n📝 Performing git operations...')

    try {
      // Run prettier from root before committing to avoid hook failures
      console.log('   Running prettier from root...')
      const rootDir = resolve(this.crispDir, '../..')
      try {
        execSync('pnpm prettier --write .', {
          cwd: rootDir,
          stdio: 'pipe',
        })
        console.log('   ✓ Prettier formatting complete')
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
      } catch (error) {
        console.warn('   ⚠️  Prettier failed, continuing anyway')
      }

      // Add all changes
      console.log('   Adding changes...')
      execSync('git add .', { cwd: this.crispDir })

      // Create commit message
      const commitMessage = `chore(crisp): publish version ${this.newVersion}

- Updated @crisp-e3/sdk to ${this.newVersion}
- Updated @crisp-e3/contracts to ${this.newVersion}
- Updated @crisp-e3/zk-inputs to ${this.newVersion}
- Published to npm`

      // Commit changes
      console.log('   Committing changes...')
      const noVerifyFlag = this.options.noVerify ? ' --no-verify' : ''
      execSync(`git commit -m "${commitMessage}"${noVerifyFlag}`, {
        cwd: this.crispDir,
        stdio: 'pipe',
      })
      console.log(`   ✓ Committed with message: "chore(crisp): publish version ${this.newVersion}"`)
    } catch (error: any) {
      console.error('❌ Error during git operations:', error.message)
      throw error
    }
  }

  /**
   * Get current version from CRISP packages
   */
  private getCurrentVersion(): string | null {
    const sdkPackagePath = join(this.crispDir, 'packages/crisp-sdk/package.json')
    if (existsSync(sdkPackagePath)) {
      const content = readFileSync(sdkPackagePath, 'utf-8')
      const packageJson = JSON.parse(content)
      if (packageJson.version) {
        return packageJson.version
      }
    }

    return null
  }

  /**
   * Update lock files after version bump
   */
  private updateLockFiles(): void {
    console.log('\n🔒 Updating lock files...')

    try {
      execSync('pnpm install', {
        cwd: this.crispDir,
        stdio: 'pipe',
      })
      console.log('   ✓ pnpm-lock.yaml updated')
    } catch {
      console.warn('   ⚠️  Could not update pnpm-lock.yaml')
    }
  }

  /**
   * Update the standalone client lock file.
   *
   * The client is deployed on its own (`pnpm install --ignore-workspace`, see
   * client/.npmrc and client/vercel.json), so it keeps a lock file which resolves
   * the CRISP packages from npm rather than from the workspace. It can only be
   * refreshed once the new version has been published.
   */
  private async updateClientLockFile(): Promise<void> {
    console.log('\n🔒 Updating the client lock file...')

    const clientDir = join(this.crispDir, 'client')

    // The registry needs a moment to serve a freshly published version, and the
    // install below resolves from it rather than from the workspace.
    await this.waitForRegistry('@crisp-e3/sdk')

    execSync('pnpm install --ignore-workspace --lockfile-only', {
      cwd: clientDir,
      stdio: 'pipe',
    })

    // A stale registry cache can resolve the previous version without failing, which
    // would produce a lock file that Vercel then rejects.
    const lockFile = readFileSync(join(clientDir, 'pnpm-lock.yaml'), 'utf-8')
    if (!lockFile.includes(`'@crisp-e3/sdk@${this.newVersion}'`)) {
      throw new Error(`client/pnpm-lock.yaml does not reference @crisp-e3/sdk@${this.newVersion} after the install`)
    }

    console.log('   ✓ client/pnpm-lock.yaml updated')
  }

  /**
   * Wait for a freshly published version to be visible on the npm registry.
   */
  private async waitForRegistry(packageName: string, attempts = 10): Promise<void> {
    for (let attempt = 1; attempt <= attempts; attempt++) {
      try {
        execSync(`npm view ${packageName}@${this.newVersion} version`, { stdio: 'pipe' })
        return
      } catch {
        if (attempt === attempts) {
          throw new Error(`${packageName}@${this.newVersion} is not available on the registry after ${attempts} attempts`)
        }
        console.log(`   … waiting for ${packageName}@${this.newVersion} on the registry (${attempt}/${attempts})`)
        await new Promise((resolve) => setTimeout(resolve, 3000))
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
   * Bump versions in CRISP npm packages
   */
  private bumpNpmPackages(): void {
    console.log('\n📦 Bumping CRISP package versions...')

    const packagesToBump = ['packages/crisp-sdk', 'packages/crisp-contracts', 'packages/crisp-zk-inputs']

    for (const packagePath of packagesToBump) {
      const fullPath = join(this.crispDir, packagePath)
      const packageJsonPath = join(fullPath, 'package.json')

      if (existsSync(packageJsonPath)) {
        this.updatePackageJson(packageJsonPath)
        const packageName = this.getPackageName(packageJsonPath)
        console.log(`   ✓ ${packageName}`)
      } else {
        console.warn(`   ⚠️  Package not found: ${packagePath}`)
      }
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

  /**
   * Update @crisp-e3/sdk dependency in client package.json
   */
  private updateClientDependency(): void {
    console.log('\n📝 Updating client dependency...')

    const clientPackagePath = join(this.crispDir, 'client/package.json')

    if (!existsSync(clientPackagePath)) {
      console.warn('   ⚠️  Client package.json not found, skipping dependency update')
      return
    }

    try {
      const content = readFileSync(clientPackagePath, 'utf-8')
      const packageJson = JSON.parse(content)

      if (packageJson.dependencies && packageJson.dependencies['@crisp-e3/sdk']) {
        const oldVersion = packageJson.dependencies['@crisp-e3/sdk']
        packageJson.dependencies['@crisp-e3/sdk'] = this.newVersion

        writeFileSync(clientPackagePath, JSON.stringify(packageJson, null, 2) + '\n')
        console.log(`   ✓ Updated @crisp-e3/sdk from ${oldVersion} to ${this.newVersion}`)
      } else {
        console.warn('   ⚠️  @crisp-e3/sdk dependency not found in client package.json')
      }
    } catch (error) {
      console.warn('   ⚠️  Could not update client dependency:', error)
    }
  }
}

// CLI interface
async function main() {
  const args = process.argv.slice(2)

  // Parse options
  const options: PublishOptions = {}
  let version: string | null = null

  for (let i = 0; i < args.length; i++) {
    const arg = args[i]

    if (arg === '--help' || arg === '-h') {
      showHelp()
      process.exit(0)
    } else if (arg === '--skip-git') {
      options.skipGit = true
    } else if (arg === '--dry-run') {
      options.dryRun = true
    } else if (arg === '--tag') {
      options.tag = args[++i]
    } else if (arg === '--no-verify') {
      options.noVerify = true
    } else if (!arg.startsWith('-')) {
      version = arg
    }
  }

  if (!version) {
    console.error('❌ Error: Version is required')
    showHelp()
    process.exit(1)
  }

  const publisher = new CRISPPublisher(version, options)
  await publisher.publishAll()
}

function showHelp() {
  console.log(`
Usage: tsx scripts/publish.ts [options] <version>

CRISP Package Publishing Script
Bumps versions, builds, and publishes CRISP npm packages.

Arguments:
  version             The new version (e.g., 1.0.0, 1.0.0-beta.1)

Options:
  --tag <name>        npm dist-tag (default: 'latest' for releases, 'next' for pre-releases)
  --skip-git          Skip all git operations (no commit)
  --dry-run           Show what would be done without making changes
  --help, -h          Show this help message

Examples:
  # Publish stable release
  tsx scripts/publish.ts 1.0.0

  # Publish beta release
  tsx scripts/publish.ts 1.0.0-beta.1

  # Publish with custom tag
  tsx scripts/publish.ts --tag canary 1.0.0-canary.1

  # Test without publishing
  tsx scripts/publish.ts --dry-run 1.0.0

  # Publish without committing
  tsx scripts/publish.ts --skip-git 1.0.0

The script will:
  1. Check for uncommitted changes
  2. Update versions in @crisp-e3/sdk, @crisp-e3/contracts, @crisp-e3/zk-inputs
  3. Update @crisp-e3/sdk dependency in client/package.json
  4. Update pnpm-lock.yaml
  5. Build packages
  6. Publish to npm
  7. Update the standalone client/pnpm-lock.yaml
  8. Commit changes (no tags)

Note: Make sure you're logged in to npm (npm login) before publishing.
`)
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    console.error('Fatal error:', error)
    process.exit(1)
  })
}

export { CRISPPublisher }
