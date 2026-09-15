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

/** The packages this script versions and publishes, in workspace order. */
const PACKAGE_DIRS = ['packages/crisp-sdk', 'packages/crisp-contracts', 'packages/crisp-zk-inputs']

/**
 * Release channels, split by BFV preset.
 *
 * The SDK inlines compiled circuit artifacts. Testing releases carry only the insecure preset so
 * they stay small; production releases carry all supported presets so one client can select the preset from
 * the E3's on-chain param set.
 *
 * Testing versions carry a prerelease identifier so npm keeps them out of ordinary ranges: a
 * consumer on `^0.18.0` can never drift onto a testing build through an update.
 *
 * `tracksClient` says whether a channel moves the client onto the version it publishes. The
 * production channel moves it because the published package contains all supported presets. Testing releases
 * leave it alone.
 *
 * `bumpsRepo` says whether a channel leaves its version behind in the working tree. It follows from
 * `tracksClient` and cannot be chosen independently: the client pins an exact version, and pnpm
 * links a workspace package only while its version still satisfies that pin. A production publish
 * leaves the workspace and client on the same exact version, so local development uses the
 * workspace and standalone deploys use the matching npm package.
 */
const PRESETS = ['insecure', 'secure-8192', 'secure-16384'] as const
type Preset = (typeof PRESETS)[number]

const CHANNELS = {
  testing: { tag: 'testing', presets: ['insecure'] as readonly Preset[], prerelease: true, tracksClient: false, bumpsRepo: false },
  prod: { tag: 'latest', presets: PRESETS, prerelease: false, tracksClient: true, bumpsRepo: true },
} as const

type Channel = keyof typeof CHANNELS

interface PublishOptions {
  skipGit?: boolean
  dryRun?: boolean
  tag?: string // npm dist-tag override; defaults to the channel's tag
  noVerify?: boolean
  channel?: Channel
}

class CRISPPublisher {
  private newVersion: string
  private oldVersion: string | null = null
  private crispDir: string
  private options: PublishOptions

  private channel: Channel

  constructor(newVersion: string, options: PublishOptions = {}) {
    this.newVersion = newVersion
    this.crispDir = resolve(__dirname, '..')
    this.options = options
    this.channel = options.channel ?? 'testing'
  }

  /** Whether this channel moves the demo client onto the version it publishes. See CHANNELS. */
  private get tracksClient(): boolean {
    return CHANNELS[this.channel].tracksClient
  }

  /**
   * Every file the version bump writes to, captured before it runs.
   *
   * Restoring from memory rather than from git keeps this correct under `--skip-git`, where the
   * working tree was never required to be clean and a checkout would discard unrelated edits.
   */
  private snapshot: Map<string, string> | null = null

  private takeSnapshot(): void {
    const paths = [
      ...PACKAGE_DIRS.map((dir) => join(this.crispDir, dir, 'package.json')),
      join(this.crispDir, 'client/package.json'),
      join(this.crispDir, 'client/pnpm-lock.yaml'),
      resolve(this.crispDir, '..', '..', 'pnpm-lock.yaml'),
    ]

    this.snapshot = new Map(paths.filter((path) => existsSync(path)).map((path) => [path, readFileSync(path, 'utf-8')]))
  }

  /**
   * Put the bumped files back.
   *
   * The lock file is restored by content, not by re-running `pnpm install`. Once the workspace
   * version has stopped satisfying the client pin, pnpm has already written a registry resolution,
   * and it keeps that entry on later installs because it is still internally valid — so an install
   * does not undo the detachment that the bump caused.
   */
  private restoreSnapshot(reason: string): void {
    if (!this.snapshot) return

    for (const [path, content] of this.snapshot) {
      writeFileSync(path, content)
    }

    console.log(`\n↩️  Restored the working tree (${reason}).`)
    console.log(`   Package versions are back at ${this.oldVersion ?? 'their previous value'}; npm keeps what was published.`)
  }

  /** Report the client pin that the selected channel may update. */
  private reportClientPin(): void {
    const pin = this.clientPin()

    if (pin === null) {
      console.warn('   ⚠️  Could not read the client pin on @crisp-e3/sdk')
      return
    }

    console.log(`📌 Client pin: ${pin}`)
  }

  /** The version the demo client currently pins, for reporting. Null when it cannot be read. */
  private clientPin(): string | null {
    try {
      const clientPackagePath = join(this.crispDir, 'client/package.json')
      return JSON.parse(readFileSync(clientPackagePath, 'utf-8')).dependencies?.['@crisp-e3/sdk'] ?? null
    } catch {
      return null
    }
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

      this.reportClientPin()

      // Check for uncommitted changes
      if (!this.options.skipGit && !this.options.dryRun) {
        this.checkGitStatus()
      }

      // In dry-run mode, just show what would happen
      if (this.options.dryRun) {
        const channel = CHANNELS[this.channel]
        const packages = ['@crisp-e3/sdk', '@crisp-e3/contracts', '@crisp-e3/zk-inputs']

        const steps: string[][] = [
          ['Update package versions in:', ...packages],
          ...(this.tracksClient ? [['Update @crisp-e3/sdk dependency in client/package.json']] : []),
          ['Update pnpm-lock.yaml'],
          [`Build packages against ${channel.presets.join(', ')}`],
          [`Publish to npm under the "${this.options.tag || channel.tag}" tag:`, ...packages],
          ...(this.tracksClient ? [['Update the standalone client/pnpm-lock.yaml']] : []),
          ...(channel.bumpsRepo
            ? this.options.skipGit
              ? []
              : [['Commit changes']]
            : [['Restore the package versions and lock files, leaving the tree unchanged']]),
        ]

        console.log('\n📋 Would perform the following actions:')
        steps.forEach(([step, ...detail], index) => {
          console.log(`   ${index + 1}. ${step}`)
          detail.forEach((line) => console.log(`      - ${line}`))
        })

        if (!this.tracksClient) {
          console.log(`\n   The client stays on ${this.clientPin() ?? 'its current pin'}; channel "${this.channel}" does not move it.`)
        }
        if (!channel.bumpsRepo) {
          console.log('   Nothing is committed: this channel restores the package version bump after publishing.')
        }

        console.log('\n✅ Dry run complete. Run without --dry-run to perform these actions.')
        return
      }

      // Everything the bump is about to touch, so it can be put back. See restoreSnapshot().
      this.takeSnapshot()

      // Bump npm packages
      this.bumpNpmPackages()

      try {
        // Update client dependency when the selected channel owns the deployable client pin.
        if (this.tracksClient) {
          this.updateClientDependency()
        }

        // Update lock files
        this.updateLockFiles()

        // Build packages
        await this.buildPackages()

        // Publish packages
        await this.publishPackages()

        // Update the client lock file, which resolves the packages from npm
        if (this.tracksClient) {
          await this.updateClientLockFile()
        } else {
          console.log(`\n↷ Channel "${this.channel}" leaves the client on its own pin (${this.clientPin() ?? 'unknown'}).`)
        }
      } catch (error) {
        // A half-bumped tree is worse than no bump: the workspace no longer matches the client pin,
        // so the next install quietly resolves the client from the registry.
        this.restoreSnapshot('the publish failed')
        throw error
      }

      if (CHANNELS[this.channel].bumpsRepo) {
        // Git operations (just commit, no tagging)
        if (!this.options.skipGit && !this.options.dryRun) {
          this.performGitOperations()
        }
      } else {
        this.restoreSnapshot(`channel "${this.channel}" does not bump the repository`)
      }

      console.log('\n✅ CRISP packages published successfully!')
      console.log('\n📋 Summary:')
      console.log(`   Previous version: ${this.oldVersion || 'unknown'}`)
      console.log(`   New version: ${this.newVersion}`)
      console.log(
        `   Channel: ${this.channel} (${CHANNELS[this.channel].presets.join(', ')}, npm tag ${this.options.tag || CHANNELS[this.channel].tag})`,
      )
      console.log(`   Packages updated: ✓`)
      console.log(`   Client dependency: ${this.tracksClient ? '✓ updated' : `↷ left on ${this.clientPin() ?? 'its own pin'}`}`)
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

        // The SDK bundles preset-bound circuits, so it builds per channel. Everything else is
        // preset-free and builds once.
        const buildScript = pkg.path === 'packages/crisp-sdk' ? `build:${this.channel}` : 'build'
        if (packageJson.scripts && packageJson.scripts[buildScript]) {
          const buildEnv = { ...process.env }
          if (CHANNELS[this.channel].presets.length === 1) {
            buildEnv.CRISP_PRESET = CHANNELS[this.channel].presets[0]
          } else {
            delete buildEnv.CRISP_PRESET
          }
          execSync(`pnpm ${buildScript}`, {
            cwd: pkgPath,
            stdio: 'inherit',
            env: buildEnv,
          })
          console.log(`   ✓ ${pkg.name} built successfully`)
        } else {
          console.log(`   ⚠️  ${pkg.name} has no ${buildScript} script, skipping`)
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

    // Dependency order. `@crisp-e3/sdk` depends on `@crisp-e3/zk-inputs`, and pnpm rewrites that
    // workspace dependency to a concrete version at pack time, so the version it names has to be on
    // the registry already — updateClientLockFile() installs from the registry right after this.
    const packagesToPublish = [
      { path: 'packages/crisp-zk-inputs', name: '@crisp-e3/zk-inputs' },
      { path: 'packages/crisp-sdk', name: '@crisp-e3/sdk' },
      { path: 'packages/crisp-contracts', name: '@crisp-e3/contracts' },
    ]

    const tag = this.options.tag || CHANNELS[this.channel].tag
    console.log(`   Channel: ${this.channel} (${CHANNELS[this.channel].presets.join(', ')}), npm tag: ${tag}`)

    for (const pkg of packagesToPublish) {
      try {
        const pkgPath = join(this.crispDir, pkg.path)

        console.log(`   Publishing ${pkg.name}...`)

        execSync(`pnpm publish --access public --tag ${tag} --no-git-checks`, {
          cwd: pkgPath,
          stdio: 'inherit',
          // `prepublishOnly` runs check-presets.mjs, which refuses to publish a channel whose
          // artifacts carry the wrong preset set. npm gives it no way to see our channel, so it
          // reads this. A custom npm dist-tag must not change the preset policy.
          env: { ...process.env, CRISP_CHANNEL: CHANNELS[this.channel].tag },
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

      // Add the exact files this script owns, including the root workspace lockfile.
      console.log('   Adding changes...')
      execSync(
        [
          'git add',
          'examples/CRISP/packages/crisp-sdk/package.json',
          'examples/CRISP/packages/crisp-contracts/package.json',
          'examples/CRISP/packages/crisp-zk-inputs/package.json',
          'examples/CRISP/client/package.json',
          'examples/CRISP/client/pnpm-lock.yaml',
          'pnpm-lock.yaml',
        ].join(' '),
        { cwd: rootDir },
      )

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

    // The prerelease identifier is what keeps the channels apart. npm excludes prereleases from
    // ordinary ranges, so a consumer on `^0.18.0` cannot drift onto a testing build through an
    // update — but only if testing versions actually carry one, and prod versions do not.
    const isPrerelease = version.includes('-')
    const expected = CHANNELS[this.channel].prerelease

    if (isPrerelease !== expected) {
      throw new Error(
        expected
          ? `Channel "testing" needs a prerelease version so it stays out of ordinary semver ranges; got ${version}. Try ${version}-insecure.0`
          : `Channel "prod" needs a plain release version; got the prerelease ${version}. Publish prereleases with --channel testing.`,
      )
    }
  }

  /**
   * Bump versions in CRISP npm packages
   */
  private bumpNpmPackages(): void {
    console.log('\n📦 Bumping CRISP package versions...')

    for (const packagePath of PACKAGE_DIRS) {
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
    } else if (arg === '--channel') {
      const value = args[++i]
      if (value !== 'testing' && value !== 'prod') {
        console.error(`❌ Error: --channel must be "testing" or "prod"; got "${value}"`)
        process.exit(1)
      }
      options.channel = value
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

  // No default. The channel decides which preset is compiled into what gets published, and picking
  // one silently is how a round ends up with an SDK and a verifier that disagree.
  if (!options.channel) {
    console.error('❌ Error: --channel is required (testing | prod)')
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
  --channel <name>    Release channel: 'testing' (insecure) or 'prod' (all presets). Required.
  --tag <name>        npm dist-tag override (default: the channel's tag)
  --skip-git          Skip all git operations (no commit)
  --dry-run           Show what would be done without making changes
  --help, -h          Show this help message

Channels:
  testing   npm tag 'testing', insecure circuits, prerelease versions only
  prod      npm tag 'latest',  all supported circuits, plain release versions only

  Testing carries one preset to stay small. Production carries all supported presets so the client can select
  the required circuit bundle from the E3's on-chain param set.

  Testing versions must carry a prerelease identifier. npm keeps prereleases out of ordinary
  ranges, so a consumer on '^0.18.0' cannot drift onto a testing build through an update.

  Only 'prod' moves the deployable client. A testing publish leaves client/package.json and
  client/pnpm-lock.yaml alone.

Prerequisite:
  The SDK build stages the circuit artifacts it needs under circuits/dist/, which git does not
  track. The testing channel stages only insecure. The production channel stages all supported presets.
  The build refuses stale or missing artifacts (pnpm -C packages/crisp-sdk check:staged <preset>).

Examples:
  # Publish to the testing channel (testnets, demos)
  tsx scripts/publish.ts --channel testing 0.18.0-insecure.0

  # Publish to production
  tsx scripts/publish.ts --channel prod 0.20.0

  # Test without publishing
  tsx scripts/publish.ts --channel testing --dry-run 0.18.0-insecure.0

  # Publish without committing
  tsx scripts/publish.ts --channel testing --skip-git 0.18.0-insecure.0

The script will:
  1. Check for uncommitted changes
  2. Update versions in @crisp-e3/sdk, @crisp-e3/contracts, @crisp-e3/zk-inputs
  2b. Build the SDK against the channel's preset set
  3. Update @crisp-e3/sdk dependency in client/package.json   (prod only)
  4. Update pnpm-lock.yaml
  5. Build packages
  6. Publish to npm in dependency order (zk-inputs, then sdk, then contracts)
  7. Update the standalone client/pnpm-lock.yaml               (prod only)
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
