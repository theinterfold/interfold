#!/usr/bin/env tsx
// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * Generate (or verify) Solidity verifier contracts from compiled Noir circuits.
 *
 * The Honk Solidity verifiers are committed to git. To keep the committed
 * files in sync with the recursive VKs, this script has two modes:
 *
 *   - `--check` (default for test/benchmark flows): regenerate in memory and
 *     diff against the committed files. Exits non-zero on drift without
 *     touching the working tree. Used by `prebuild.sh`, `extract_crisp_verify_gas.sh`,
 *     `replay_folded_verify_gas.sh` so accidental drift fails loudly instead
 *     of silently rewriting committed contracts mid-test.
 *
 *   - `--write` (default for manual runs): regenerate and overwrite the
 *     committed `.sol` files. Use this when you intentionally bump circuits.
 *
 * Prerequisites:
 *   - `nargo` and `bb` (Barretenberg CLI) must be installed and in PATH
 *   - Circuits should be compiled first (`pnpm build:circuits`) or this script
 *     will compile them automatically.
 *
 * Usage:
 *   pnpm generate:verifiers                       # Write all circuits (default)
 *   pnpm generate:verifiers --check               # Verify committed verifiers match VKs (no writes)
 *   pnpm generate:verifiers --circuits pk,fold    # Specific circuits
 *   pnpm generate:verifiers --clean               # Remove existing verifiers first (write mode only)
 *   pnpm generate:verifiers --dry-run             # Show what would be generated
 *   pnpm generate:verifiers --no-compile          # Use artifacts from build:circuits (skips target cleanup)
 */

import { execFileSync, execSync } from 'child_process'
import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'fs'
import { basename, join, resolve } from 'path'
import {
  ALL_COMMITTEES,
  ALL_GROUPS,
  ALL_PRESETS,
  CIRCUIT_COMMITTEES,
  CIRCUIT_GROUPS,
  type CircuitCommittee,
  type CircuitGroup,
} from './circuit-constants'

// ---------------------------------------------------------------------------
// Types & constants
// ---------------------------------------------------------------------------

const LICENSE_HEADER = `// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
`

/**
 * Canonical BFV preset for the committed Honk Solidity verifiers.
 *
 * The on-chain `DkgAggregatorVerifier.sol` / `DecryptionAggregatorVerifier.sol` bake in the
 * recursive VKs of `dkg_aggregator` / `decryption_aggregator`, which are
 * **preset-dependent**: different BFV parameter sets compile to different VKs and therefore
 * different `.sol` bytes. Exactly one preset can be "the committed one"; we pin `insecure-512`
 * because that is the development/CI/benchmark default and the preset every committed verifier
 * corresponds to.
 *
 * Both `--check` and `--write` refuse to run unless
 * `dist/circuits/<CANONICAL_PRESET>/.build-stamp.json` exists and its `preset` field matches.
 * This prevents silently producing/checking against the wrong preset's VKs — e.g. after
 * `pnpm build:circuits --preset secure-8192`, where `circuits/bin/` holds secure artifacts that
 * would generate different `.sol` bytes.
 *
 * If you need verifiers for a different preset (e.g. a production deploy on `secure-8192`),
 * rebuild that preset locally and run the generator there; do **not** commit the result over
 * the canonical files.
 */
const CANONICAL_PRESET = 'insecure-512'

/**
 * Canonical committee for the committed Honk Solidity verifiers under
 * `contracts/verifiers/bfv/honk/`. The committee determines `H` and `T` of the
 * `dkg_aggregator` / `decryption_aggregator` circuits — different committees compile
 * to different recursive VKs, so each committee's verifiers must land in a separate
 * directory to coexist on disk. `minimum` is the development/CI default; other committees
 * generate under `honk/<committee>/`.
 */
const CANONICAL_COMMITTEE: CircuitCommittee = CIRCUIT_COMMITTEES.MINIMUM

interface CircuitInfo {
  name: string
  group: CircuitGroup
  path: string
  packageName: string
}

interface GenerateOptions {
  groups?: CircuitGroup[]
  circuits?: string[]
  clean?: boolean
  dryRun?: boolean
  compile?: boolean // compile circuits before generating verifiers
  noCleanTargets?: boolean // skip deleting nargo target dirs before generation
  /**
   * Check mode: generate verifiers into memory and diff against the committed
   * files. Exit non-zero on any drift. No writes to the working tree.
   * Used by test/benchmark/CI flows that must not silently mutate committed
   * verifier contracts.
   */
  check?: boolean
  /** BFV preset whose artifacts in `circuits/bin/` are used for generation/check. */
  preset?: string
  /**
   * Committee whose `H`/`T` baked into the wrapper verifiers should be used.
   * When unset, read from `circuits/bin/.active-preset.json`. Non-canonical
   * committees land under `honk/<committee>/` so they don't overwrite the
   * committed canonical-committee `.sol` files.
   */
  committee?: CircuitCommittee
  /** Override output directory (write mode only). Defaults to committed honk/ path. */
  outputDir?: string
}

// ---------------------------------------------------------------------------
// Main class
// ---------------------------------------------------------------------------

class VerifierGenerator {
  private rootDir: string
  private circuitsDir: string
  private verifierDir: string
  private options: GenerateOptions

  constructor(rootDir?: string, options: GenerateOptions = {}) {
    this.rootDir = rootDir ?? resolve(__dirname, '..')
    this.circuitsDir = join(this.rootDir, 'circuits', 'bin')
    this.options = {
      groups: ALL_GROUPS,
      clean: false,
      compile: true,
      ...options,
    }
    this.verifierDir = options.outputDir !== undefined ? resolve(options.outputDir) : this.defaultVerifierDir(this.targetCommittee())
  }

  private defaultVerifierDir(committee: CircuitCommittee): string {
    const honkBase = join(this.rootDir, 'packages', 'interfold-contracts', 'contracts', 'verifiers', 'bfv', 'honk')
    // Non-canonical committees go under honk/<committee>/ so canonical-committee verifiers
    // committed to git aren't clobbered.
    return committee !== CANONICAL_COMMITTEE ? join(honkBase, committee) : honkBase
  }

  /** Reads `.active-preset.json::committee` or falls back to the canonical committee. */
  private targetCommittee(): CircuitCommittee {
    if (this.options.committee) return this.options.committee
    const activePath = join(this.circuitsDir, '.active-preset.json')
    if (existsSync(activePath)) {
      try {
        const v = JSON.parse(readFileSync(activePath, 'utf-8')) as { committee?: string }
        if (v.committee && (ALL_COMMITTEES as string[]).includes(v.committee)) {
          return v.committee as CircuitCommittee
        }
      } catch {
        // fall through
      }
    }
    return CANONICAL_COMMITTEE
  }

  async generate(): Promise<void> {
    const mode = this.options.check ? 'Checking' : 'Generating'
    console.log(`🔮 ${mode} Solidity verifiers from Noir circuits...\n`)

    this.checkTool('nargo --version', 'nargo')
    this.checkTool('bb --version', 'bb')

    const targetPreset = this.targetPreset()

    const targetCommittee = this.targetCommittee()

    if (!this.options.dryRun) {
      this.assertPresetBuilt(targetPreset)
      this.assertCircuitsBinActivePreset(targetPreset)
      this.assertCircuitsBinActiveCommittee(targetCommittee)
    }

    // Committed Honk `.sol` files are pinned to (CANONICAL_PRESET, CANONICAL_COMMITTEE). Any other
    // (preset, committee) is a per-deploy variant — generated under honk/<committee>/ (or skipped
    // entirely in --check mode since there's no canonical to diff against).
    if (this.options.check && (targetPreset !== CANONICAL_PRESET || targetCommittee !== CANONICAL_COMMITTEE)) {
      console.log(
        `\n✅ (preset=${targetPreset}, committee=${targetCommittee}) is built and active in circuits/bin.\n` +
          `   Committed Honk verifiers are pinned to (${CANONICAL_PRESET}, ${CANONICAL_COMMITTEE}); skipping .sol diff.\n` +
          `   Benchmark / deploy flows generate fresh aggregator verifiers under honk/${targetCommittee}/ at runtime.\n`,
      )
      return
    }

    const circuits = this.discoverCircuits()
    if (circuits.length === 0) {
      console.log('   ⚠️  No circuits found')
      return
    }

    console.log(`   Found ${circuits.length} circuit(s)\n`)

    if (this.options.dryRun) {
      console.log('   Would generate verifiers for:', circuits.map((c) => `${c.group}/${c.name}`).join(', '))
      console.log(`   Output directory: ${this.verifierDir}`)
      return
    }

    // Clean stale nargo build caches unless caller just ran build:circuits (--no-compile / --no-clean-targets).
    if (!this.options.noCleanTargets && this.options.compile !== false) {
      this.cleanTargetDirs(circuits)
    }

    if (this.options.check && this.options.clean) {
      throw new Error('--check and --clean are mutually exclusive (check must not mutate the working tree)')
    }

    // In write mode, prepare output directory.
    if (!this.options.check) {
      if (this.options.clean && existsSync(this.verifierDir)) {
        rmSync(this.verifierDir, { recursive: true })
        console.log('   🗑️  Cleaned existing verifier directory')
      }
      mkdirSync(this.verifierDir, { recursive: true })
    } else if (!existsSync(this.verifierDir)) {
      throw new Error(`--check requires the committed verifier directory to exist: ${this.verifierDir}`)
    }

    // Pre-flight: two circuits with the same leaf name would silently overwrite each other's .sol.
    const seen = new Map<string, string>()
    for (const circuit of circuits) {
      const contractFile = `${this.toContractName(circuit.name)}.sol`
      const prior = seen.get(contractFile)
      if (prior) {
        throw new Error(
          `Duplicate Solidity verifier filename ${contractFile} for circuits ` +
            `${prior} and ${circuit.group}/${circuit.name}; rename one of the circuits or ` +
            `extend toContractName to include the group prefix.`,
        )
      }
      seen.set(contractFile, `${circuit.group}/${circuit.name}`)
    }

    const processed: string[] = []
    const drift: { circuit: string; file: string; reason: string }[] = []
    const errors: string[] = []

    for (const circuit of circuits) {
      try {
        const result = this.generateVerifier(circuit)
        processed.push(result.outputPath)
        if (this.options.check) {
          if (!existsSync(result.outputPath)) {
            drift.push({
              circuit: `${circuit.group}/${circuit.name}`,
              file: result.outputPath,
              reason: 'committed file is missing',
            })
          } else {
            const committed = readFileSync(result.outputPath, 'utf-8')
            if (committed !== result.content) {
              drift.push({
                circuit: `${circuit.group}/${circuit.name}`,
                file: result.outputPath,
                reason: 'content differs from committed file',
              })
            }
          }
        }
      } catch (error: any) {
        errors.push(`${circuit.group}/${circuit.name}: ${error.message}`)
        console.error(`   ✗ ${circuit.group}/${circuit.name}: ${error.message}`)
      }
    }

    if (this.options.check) {
      if (drift.length > 0) {
        console.error(`\n❌ ${drift.length} Solidity verifier(s) drift from current circuit VKs:`)
        for (const d of drift) {
          console.error(`   • ${d.circuit} (${basename(d.file)}): ${d.reason}`)
        }
        console.error(
          `\n   The committed Honk verifiers under contracts/verifiers/bfv/honk are out of sync\n` +
            `   with the circuits' recursive VKs. This usually means:\n` +
            `     - You ran 'pnpm build:circuits' against a different Noir/bb version, or\n` +
            `     - A circuit / VK changed without regenerating the committed Solidity files.\n` +
            `\n   To fix:\n` +
            `     1. Verify your Noir/bb versions match (see crates/zk-prover/versions.json).\n` +
            `     2. Run 'pnpm build:circuits --preset insecure-512' (or the relevant preset).\n` +
            `     3. Run 'pnpm generate:verifiers --write' (or omit --check) to refresh the\n` +
            `        committed .sol files, then commit the diff.\n`,
        )
        process.exit(1)
      }
      console.log(`\n✅ Checked ${processed.length} Solidity verifier(s) — all in sync with current VKs.\n`)
      for (const f of processed) console.log(`   • ${basename(f)}`)
    } else {
      console.log(`\n✅ Generated ${processed.length} Solidity verifier(s) in:`)
      console.log(`   ${this.verifierDir}\n`)
      for (const f of processed) console.log(`   • ${basename(f)}`)
    }

    if (errors.length > 0) {
      console.error(`\n❌ ${errors.length} error(s):`)
      for (const e of errors) console.error(`   • ${e}`)
      process.exit(1)
    }
  }

  // -------------------------------------------------------------------------
  // Discovery
  // -------------------------------------------------------------------------

  private discoverCircuits(): CircuitInfo[] {
    const circuits: CircuitInfo[] = []
    if (!existsSync(this.circuitsDir)) return circuits

    // When --circuits not specified, include all circuits
    const circuitFilter = this.options.circuits?.length ? this.options.circuits : undefined

    for (const group of this.options.groups ?? ALL_GROUPS) {
      const groupDir = join(this.circuitsDir, group)
      if (!existsSync(groupDir)) continue

      for (const entry of readdirSync(groupDir)) {
        const circuitPath = join(groupDir, entry)
        if (statSync(circuitPath).isDirectory() && existsSync(join(circuitPath, 'Nargo.toml'))) {
          if (!circuitFilter || circuitFilter.includes(entry)) {
            const packageName = this.getPackageName(circuitPath)
            circuits.push({ name: entry, group, path: circuitPath, packageName })
          }
        }
      }
    }
    return circuits
  }

  private getPackageName(circuitPath: string): string {
    try {
      const content = readFileSync(join(circuitPath, 'Nargo.toml'), 'utf-8')
      const match = content.match(/^name\s*=\s*"([^"]+)"/m)
      if (match) return match[1]
    } catch {
      // fall through
    }
    return basename(circuitPath)
  }

  // -------------------------------------------------------------------------
  // Generation pipeline  (compile → write_vk → write_solidity_verifier)
  // -------------------------------------------------------------------------

  private generateVerifier(circuit: CircuitInfo): { content: string; outputPath: string } {
    const { name, group, packageName } = circuit

    // 1. Compile if needed
    const jsonFile = this.ensureCompiled(circuit)

    // 2. Generate VK
    const targetDir = this.findTargetDir(circuit, packageName)
    const vkPath = this.ensureVk(jsonFile, targetDir, packageName)

    // 3. Generate Solidity verifier
    const rawSolPath = join(targetDir, `${packageName}_verifier.sol`)
    execFileSync('bb', ['write_solidity_verifier', '-k', vkPath, '-o', rawSolPath], { stdio: 'pipe' })

    if (!existsSync(rawSolPath)) {
      throw new Error('bb write_solidity_verifier did not produce output')
    }

    // 4. Post-process: rename contract, add license header
    const contractName = this.toContractName(name)
    const outputFileName = `${contractName}.sol`
    const outputPath = join(this.verifierDir, outputFileName)

    let solidity = readFileSync(rawSolPath, 'utf-8')

    // Replace the default contract name (HonkVerifier) with our descriptive name
    solidity = solidity.replace(/contract\s+HonkVerifier/g, `contract ${contractName}`)

    // Replace license header – bb produces Apache-2.0 by default
    solidity = solidity.replace(/\/\/\s*SPDX-License-Identifier:[^\n]*\n(\/\/[^\n]*\n)*/, LICENSE_HEADER)

    // Clean up intermediate file (always — we don't keep the bb temp output around)
    rmSync(rawSolPath, { force: true })

    // Normalize with prettier so the on-disk format matches what the rest of
    // the repo's `pnpm prettier:write` produces. Without this, --check would
    // always fail because bb emits a different whitespace style than
    // prettier-plugin-solidity.
    solidity = this.formatSolidity(solidity, outputPath)

    // In check mode, do not touch the committed file.
    if (!this.options.check) {
      writeFileSync(outputPath, solidity)
      console.log(`   ✓ ${group}/${name} → ${outputFileName}`)
    } else {
      console.log(`   • ${group}/${name} → ${outputFileName} (checking)`)
    }

    return { content: solidity, outputPath }
  }

  /**
   * Format Solidity through prettier-plugin-solidity so output matches the
   * project's standard formatting. Run from `packages/interfold-contracts` so
   * prettier picks up the local `.prettierrc` and plugin resolution.
   */
  private formatSolidity(content: string, outputPath: string): string {
    const contractsDir = join(this.rootDir, 'packages', 'interfold-contracts')
    // Use prettier --stdin-filepath so plugin selection is by extension.
    const result = execFileSync('pnpm', ['exec', 'prettier', '--stdin-filepath', outputPath], {
      cwd: contractsDir,
      input: content,
      stdio: ['pipe', 'pipe', 'pipe'],
    })
    return result.toString('utf-8')
  }

  /**
   * Ensure the circuit is compiled and return the path to the JSON artifact.
   */
  private ensureCompiled(circuit: CircuitInfo): string {
    const targetDirs = this.candidateTargetDirs(circuit)

    // Check if already compiled
    for (const dir of targetDirs) {
      const candidate = join(dir, `${circuit.packageName}.json`)
      if (existsSync(candidate)) return candidate
    }

    // Compile
    if (!this.options.compile) {
      throw new Error(`Compiled artifact ${circuit.packageName}.json not found. Run 'pnpm build:circuits' first or remove --no-compile.`)
    }

    console.log(`   ⏳ Compiling ${circuit.group}/${circuit.name}...`)
    execSync('nargo compile', { cwd: circuit.path, stdio: 'pipe' })

    // Search again
    for (const dir of targetDirs) {
      const candidate = join(dir, `${circuit.packageName}.json`)
      if (existsSync(candidate)) return candidate
    }

    throw new Error(`Compiled artifact ${circuit.packageName}.json not found after compilation`)
  }

  /**
   * Ensure VK exists and return its path.
   */
  private ensureVk(jsonFile: string, targetDir: string, packageName: string): string {
    const vkFile = join(targetDir, `${packageName}.vk`)

    // Check if VK already exists
    if (existsSync(vkFile)) return vkFile

    // Also check for a bare 'vk' file
    const defaultVk = join(targetDir, 'vk')
    if (existsSync(defaultVk)) {
      copyFileSync(defaultVk, vkFile)
      return vkFile
    }

    // Generate VK (EVM target for Solidity verifiers)
    execFileSync('bb', ['write_vk', '-b', jsonFile, '-o', targetDir, '-t', 'evm'], { stdio: 'pipe' })

    // bb writes to 'vk' by default, rename to <packageName>.vk
    if (existsSync(defaultVk) && !existsSync(vkFile)) {
      copyFileSync(defaultVk, vkFile)
      rmSync(defaultVk, { force: true })
    }

    if (!existsSync(vkFile)) {
      throw new Error(`Failed to generate verification key for ${packageName}`)
    }

    return vkFile
  }

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  private candidateTargetDirs(circuit: CircuitInfo): string[] {
    const groupDir = join(this.circuitsDir, circuit.group)
    return [join(groupDir, 'target'), join(this.circuitsDir, 'target'), join(circuit.path, 'target')]
  }

  private findTargetDir(circuit: CircuitInfo, packageName: string): string {
    for (const dir of this.candidateTargetDirs(circuit)) {
      const candidate = join(dir, `${packageName}.json`)
      if (existsSync(candidate)) return dir
    }
    throw new Error(`Target directory not found for ${circuit.group}/${circuit.name}`)
  }

  /**
   * Convert circuit folder name to a PascalCase Solidity contract name.
   * e.g. dkg_aggregator → DkgAggregatorVerifier, decryption_aggregator → DecryptionAggregatorVerifier
   */
  private toContractName(name: string): string {
    const pascal = (s: string) =>
      s
        .split(/[_-]+/)
        .map((w) => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase())
        .join('')
    return `${pascal(name)}Verifier`
  }

  /**
   * Remove all nargo target directories to prevent stale cached artifacts
   * from being picked up instead of freshly compiled ones.
   */
  private cleanTargetDirs(circuits: CircuitInfo[]): void {
    const cleaned = new Set<string>()
    for (const circuit of circuits) {
      const groupTarget = join(this.circuitsDir, circuit.group, 'target')
      if (!cleaned.has(groupTarget) && existsSync(groupTarget)) {
        rmSync(groupTarget, { recursive: true })
        cleaned.add(groupTarget)
      }
      const circuitTarget = join(circuit.path, 'target')
      if (!cleaned.has(circuitTarget) && existsSync(circuitTarget)) {
        rmSync(circuitTarget, { recursive: true })
        cleaned.add(circuitTarget)
      }
    }
    const rootTarget = join(this.circuitsDir, 'target')
    if (existsSync(rootTarget)) {
      rmSync(rootTarget, { recursive: true })
      cleaned.add(rootTarget)
    }
    if (cleaned.size > 0) {
      console.log(`   🧹 Cleaned ${cleaned.size} stale target dir(s)`)
    }
  }

  private checkTool(cmd: string, name: string): void {
    try {
      execSync(cmd, { stdio: ['pipe', 'pipe', 'pipe'] })
    } catch {
      throw new Error(`${name} is not installed or not in PATH`)
    }
  }

  private targetPreset(): string {
    return this.options.preset ?? CANONICAL_PRESET
  }

  /**
   * Refuse to run unless `dist/circuits/<preset>/<committee>/.build-stamp.json` exists.
   */
  private assertPresetBuilt(preset: string): void {
    const committee = this.targetCommittee()
    const stampPath = join(this.rootDir, 'dist', 'circuits', preset, committee, '.build-stamp.json')
    if (!existsSync(stampPath)) {
      throw new Error(
        `Preset '${preset}' is not built (missing ${stampPath}).\n` +
          `\n` +
          `   To fix, run from the repo root:\n` +
          `     pnpm build:circuits --preset ${preset} --committee ${committee}\n` +
          `   then retry.`,
      )
    }
    let stamp: { preset?: string } = {}
    try {
      stamp = JSON.parse(readFileSync(stampPath, 'utf-8'))
    } catch (err: any) {
      throw new Error(`Failed to parse ${stampPath}: ${err.message}`)
    }
    if (stamp.preset !== preset) {
      throw new Error(
        `Build stamp at ${stampPath} reports preset '${stamp.preset ?? '(missing)'}', expected '${preset}'.\n` +
          `   Run:\n` +
          `     pnpm build:circuits --preset ${preset} --committee ${committee}\n` +
          `   then retry.`,
      )
    }
    console.log(`   ✓ Preset '${preset}/${committee}' build stamp present in dist/circuits.\n`)
  }

  /**
   * Ensure `circuits/bin/` was last populated by `build:circuits` for the same preset.
   * Without this, a secure benchmark could leave secure VKs in bin while `--check` diffs
   * against committed insecure-512 `.sol` files.
   */
  private assertCircuitsBinActivePreset(preset: string): void {
    const activePath = join(this.circuitsDir, '.active-preset.json')
    if (!existsSync(activePath)) {
      throw new Error(
        `Missing ${activePath} (which preset last built circuits/bin is unknown).\n` +
          `   If dist/circuits/${preset}/ is already built, hydrate bin in seconds:\n` +
          `     pnpm build:circuits --preset ${preset} --skip-if-built --no-clean --no-clean-targets\n` +
          `   Otherwise run a full compile:\n` +
          `     pnpm build:circuits --preset ${preset}`,
      )
    }
    let active: { preset?: string } = {}
    try {
      active = JSON.parse(readFileSync(activePath, 'utf-8'))
    } catch (err: any) {
      throw new Error(`Failed to parse ${activePath}: ${err.message}`)
    }
    if (active.preset !== preset) {
      throw new Error(
        `circuits/bin was last built for preset '${active.preset ?? '(missing)'}', but this run targets '${preset}'.\n` +
          `   Fast fix (reuses dist/circuits/${preset}/, no full recompile):\n` +
          `     pnpm build:circuits --preset ${preset} --skip-if-built --no-clean --no-clean-targets\n` +
          `   Full compile only if dist is missing or stale:\n` +
          `     pnpm build:circuits --preset ${preset}`,
      )
    }
    console.log(`   ✓ circuits/bin active preset matches '${preset}'.\n`)
  }

  /**
   * Mirror of `assertCircuitsBinActivePreset` for the committee axis. When the active
   * committee on disk doesn't match the one we're generating for, the resulting `.sol`
   * verifiers would bake in the wrong H/T and silently disagree with on-chain calldata.
   */
  private assertCircuitsBinActiveCommittee(committee: CircuitCommittee): void {
    const activePath = join(this.circuitsDir, '.active-preset.json')
    if (!existsSync(activePath)) return // already errored in preset check; nothing extra to say
    let active: { committee?: string } = {}
    try {
      active = JSON.parse(readFileSync(activePath, 'utf-8'))
    } catch {
      return
    }
    if (!active.committee) {
      console.warn(`   ⚠️  ${activePath} has no \`committee\` field (older build). Skipping committee cross-check.\n`)
      return
    }
    if (active.committee !== committee) {
      throw new Error(
        `circuits/bin was last built for committee '${active.committee}', but this run targets '${committee}'.\n` +
          `   Rebuild with:\n` +
          `     pnpm build:circuits --committee ${committee}`,
      )
    }
    console.log(`   ✓ circuits/bin active committee matches '${committee}'.\n`)
  }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

async function main() {
  const args = process.argv.slice(2)
  const options: GenerateOptions = {}

  for (let i = 0; i < args.length; i++) {
    const arg = args[i]
    if (arg === '-h' || arg === '--help') {
      showHelp()
      process.exit(0)
    } else if (arg === '--dry-run') {
      options.dryRun = true
    } else if (arg === '--clean') {
      options.clean = true
    } else if (arg === '--no-compile') {
      options.compile = false
      options.noCleanTargets = true
    } else if (arg === '--no-clean-targets') {
      options.noCleanTargets = true
    } else if (arg === '--check') {
      options.check = true
    } else if (arg === '--write') {
      options.check = false
    } else if (arg === '--preset') {
      const value = args[++i]
      if (!value || value.startsWith('--')) {
        console.error('Error: --preset requires a value (insecure-512 | secure-8192)')
        process.exit(1)
      }
      if (!ALL_PRESETS.includes(value as (typeof ALL_PRESETS)[number])) {
        console.error(`Error: unknown preset '${value}'. Expected one of: ${ALL_PRESETS.join(', ')}`)
        process.exit(1)
      }
      options.preset = value
    } else if (arg === '--committee') {
      const value = args[++i]
      if (!value || value.startsWith('--')) {
        console.error(`Error: --committee requires a value (${ALL_COMMITTEES.join('|')})`)
        process.exit(1)
      }
      if (!(ALL_COMMITTEES as readonly string[]).includes(value)) {
        console.error(`Error: unknown committee '${value}'. Expected one of: ${ALL_COMMITTEES.join(', ')}`)
        process.exit(1)
      }
      options.committee = value as CircuitCommittee
    } else if (arg === '--output-dir') {
      const value = args[++i]
      if (!value || value.startsWith('--')) {
        console.error('Error: --output-dir requires a path')
        process.exit(1)
      }
      options.outputDir = value
    } else if (arg === '--group') {
      const value = args[++i]
      if (!value || value.startsWith('--')) {
        console.error('Error: --group requires a value')
        process.exit(1)
      }
      options.groups = value.split(',') as CircuitGroup[]
    } else if (arg === '--circuits') {
      const value = args[++i]
      if (!value || value.startsWith('--')) {
        console.error('Error: --circuits requires a value')
        process.exit(1)
      }
      options.circuits = value.split(',').map((s) => s.trim())
    }
  }

  const generator = new VerifierGenerator(undefined, options)
  await generator.generate()
}

function showHelp() {
  console.log(`
Usage: generate-verifiers [options]

Generates (or verifies) Solidity Honk verifier contracts from compiled Noir
circuits and places them in packages/interfold-contracts/contracts/verifiers/bfv/honk/.

The Solidity verifiers are committed to git. Test and benchmark flows run
this script with --check so accidental drift between committed verifiers and
current circuit VKs is surfaced as a failure rather than a silent rewrite.

Options:
  --check                Verify committed verifiers match current VKs (no writes).
                         Exits non-zero on drift. Used by test/benchmark/CI flows.
  --preset <name>        BFV preset for circuits/bin (insecure-512 | secure-8192).
                         Defaults to insecure-512. With --check and a non-insecure preset,
                         only verifies dist/ + circuits/bin alignment (no .sol diff).
  --committee <name>     Committee size (minimum | micro | small). When omitted, read from
                         circuits/bin/.active-preset.json. Non-canonical committees write
                         to honk/<committee>/ so committed canonical files are not clobbered.
  --output-dir <path>    Write generated verifiers here instead of the committed honk/ dir.
  --write                Write/overwrite committed verifiers (this is the default
                         when neither --check nor --write is passed).
  --circuits <list>      Circuit names (comma-separated). When omitted, generates all circuits.
  --group <groups>       Circuit groups (comma-separated: dkg,threshold,recursive_aggregation)
  --clean                Remove existing verifier directory before generating (write mode only).
  --no-compile           Don't compile circuits automatically (fail if not already compiled);
                         also skips cleaning nargo target dirs (use after build:circuits).
  --no-clean-targets     Don't delete nargo target dirs before generating verifiers.
  --dry-run              Show what would be generated without doing anything.
  -h, --help             Show this help message.

Examples:
  pnpm generate:verifiers                                # Rewrite committed verifiers (manual)
  pnpm generate:verifiers --check                        # Verify committed verifiers (CI/tests)
  pnpm generate:verifiers --circuits dkg_aggregator      # Single circuit
  pnpm generate:verifiers --check --no-compile           # Verify against existing artifacts only
`)
}

if (require.main === module) {
  main().catch((err: unknown) => {
    const msg = err instanceof Error ? err.message : String(err)
    console.error(`\n❌ ${msg}\n`)
    process.exit(1)
  })
}

export { VerifierGenerator, GenerateOptions, CircuitGroup, CIRCUIT_GROUPS }
