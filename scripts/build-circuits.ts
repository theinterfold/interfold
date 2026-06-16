#!/usr/bin/env tsx
// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { execSync } from 'child_process'
import { createHash } from 'crypto'
import { appendFileSync, copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'fs'
import { basename, join, resolve } from 'path'
import {
  ALL_COMMITTEES,
  ALL_GROUPS,
  ALL_PRESETS,
  CIRCUIT_COMMITTEES,
  CIRCUIT_GROUPS,
  CIRCUIT_PRESETS,
  CIRCUIT_VARIANTS,
  COMMITTEE_PARAMS,
  isPresetCommitteeSupported,
  PRESET_NOIR_CONFIG,
  type CircuitCommittee,
  type CircuitGroup,
  type CircuitPreset,
} from './circuit-constants'

interface CircuitInfo {
  name: string
  group: CircuitGroup
  path: string
}
interface CompiledCircuit {
  name: string
  group: CircuitGroup
  preset: string
  committee: CircuitCommittee
  artifacts: {
    json?: string
    vk?: string
    vkHash?: string
    vkRecursive?: string
    vkRecursiveHash?: string
    vkNoir?: string
    vkNoirHash?: string
  }
  checksums: {
    json?: string
    vk?: string
    vkHash?: string
    vkRecursive?: string
    vkRecursiveHash?: string
    vkNoir?: string
    vkNoirHash?: string
  }
}
interface BuildOptions {
  groups?: CircuitGroup[]
  circuits?: string[]
  skipChecksums?: boolean
  skipVk?: boolean
  outputDir?: string
  clean?: boolean
  noCleanTargets?: boolean
  skipIfBuilt?: boolean
  /** Copy dist/circuits/<preset>/ artifacts into circuits/bin without nargo compile. */
  hydrateBinOnly?: boolean
  dryRun?: boolean
  preset?: CircuitPreset | 'all'
  /** Active committee size — drives `committee/active.nr` and verifier H/T. Pass `'all'` to build every committee. */
  committee?: CircuitCommittee | 'all'
  /** Skip writing BFV_DKG_H/T into `packages/interfold-contracts/scripts/utils.ts`. */
  skipUtilsPatch?: boolean
}

interface PresetBuildStamp {
  preset: string
  /** Committee selection at build time. Optional for backward compat with older stamps. */
  committee?: CircuitCommittee
  sourceHash: string
  builtAt: string
}
interface BuildResult {
  success: boolean
  compiled: CompiledCircuit[]
  checksumFile?: string
  releaseDir?: string
  errors: string[]
  sourceHash?: string
}

class NoirCircuitBuilder {
  private rootDir: string
  private circuitsDir: string
  private options: BuildOptions

  constructor(rootDir?: string, options: BuildOptions = {}) {
    this.rootDir = rootDir ?? resolve(__dirname, '..')
    this.circuitsDir = join(this.rootDir, 'circuits', 'bin')
    this.options = {
      groups: ALL_GROUPS,
      outputDir: join(this.rootDir, 'dist', 'circuits'),
      clean: true,
      skipVk: false,
      preset: CIRCUIT_PRESETS.INSECURE_512,
      committee: CIRCUIT_COMMITTEES.MINIMUM,
      ...options,
    }

    if (this.options.preset !== 'all' && this.options.committee && this.options.committee !== 'all') {
      if (!isPresetCommitteeSupported(this.options.preset as CircuitPreset, this.options.committee)) {
        throw new Error(
          `Unsupported preset/committee pair (${this.options.preset}, ${this.options.committee}). ` +
            `This combination currently emits stub parity matrices and invalid proofs.`,
        )
      }
    }
  }

  async buildAll(): Promise<BuildResult> {
    const result: BuildResult = { success: true, compiled: [], errors: [] }
    const presets: CircuitPreset[] = this.options.preset === 'all' ? ALL_PRESETS : [this.options.preset!]
    const committees: CircuitCommittee[] =
      this.options.committee === 'all' ? ALL_COMMITTEES : [this.options.committee ?? CIRCUIT_COMMITTEES.MINIMUM]

    console.log(`🔮 Building Noir circuits for preset(s): ${presets.join(', ')}, committee(s): ${committees.join(', ')}...`)

    const modNrPath = join(this.rootDir, 'circuits', 'lib', 'src', 'configs', 'default', 'mod.nr')

    // Preset and committee selections are persistent. They're written into `default/mod.nr`
    // (preset) and `committee/active.nr` (committee) by `setNoirConfigPreset` / `setNoirCommittee`
    // below and intentionally left on disk so the operator's choice survives the build.
    // No save/restore — see `pnpm check:committee` for the drift guard.

    if (this.options.clean && existsSync(this.options.outputDir!)) {
      rmSync(this.options.outputDir!, { recursive: true })
    }
    mkdirSync(this.options.outputDir!, { recursive: true })

    for (const preset of presets) {
      for (const committee of committees) {
        const presetResult = await this.buildForPreset(preset, committee, modNrPath)
        result.compiled.push(...presetResult.compiled)
        result.errors.push(...presetResult.errors)
        if (!presetResult.success) result.success = false
        if (presetResult.sourceHash && !result.sourceHash) result.sourceHash = presetResult.sourceHash
      }
    }

    if (!this.options.skipChecksums && result.compiled.length > 0) {
      result.checksumFile = this.generateChecksumFile(result.compiled)
    }
    result.releaseDir = this.options.outputDir!

    return result
  }

  private setNoirConfigPreset(modNrPath: string, preset: CircuitPreset): void {
    const configModule = PRESET_NOIR_CONFIG[preset]
    const content = [
      '// SPDX-License-Identifier: LGPL-3.0-only',
      '//',
      '// This file is provided WITHOUT ANY WARRANTY;',
      '// without even the implied warranty of MERCHANTABILITY',
      '// or FITNESS FOR A PARTICULAR PURPOSE.',
      '//',
      `// Auto-generated by build-circuits.ts for preset: ${preset}`,
      '',
      '// Committee size (N_PARTIES / T / H) is routed through `committee::active`,',
      '// which `build-circuits.ts` regenerates atomically with this file.',
      `pub use super::committee::active::{H, N_PARTIES, T};`,
      `pub use super::${configModule}::dkg;`,
      `pub use super::${configModule}::threshold;`,
      '',
      '/// Max number of non-zero coefficients in the message polynomial.',
      '/// This is a conservative estimate that should be okay for most use cases.',
      'pub global MAX_MSG_NON_ZERO_COEFFS: u32 = 100;',
      '',
    ].join('\n')
    writeFileSync(modNrPath, content)
    console.log(`   📋 Set Noir config to: ${configModule} (preset: ${preset})`)
  }

  /** Regenerates `committee/active.nr` to re-export from the chosen leaf module. */
  private setNoirCommittee(committee: CircuitCommittee): void {
    const activeNrPath = join(this.rootDir, 'circuits', 'lib', 'src', 'configs', 'committee', 'active.nr')
    const content = [
      '// SPDX-License-Identifier: LGPL-3.0-only',
      '//',
      '// This file is provided WITHOUT ANY WARRANTY;',
      '// without even the implied warranty of MERCHANTABILITY',
      '// or FITNESS FOR A PARTICULAR PURPOSE.',
      '//',
      `// Auto-generated by scripts/build-circuits.ts for committee: ${committee}`,
      '// Single source of truth for the active committee size in the Noir codebase.',
      '//',
      '// Importing modules MUST NOT reach into `committee::{minimum,micro,small}` directly;',
      '// always go through `committee::active` so that switching committee is a one-file edit.',
      '//',
      '// This module also breaks the import cycle that would arise from',
      '// `math::committee_hash` -> `configs::default` -> `configs::insecure::threshold` -> `math`:',
      '// `committee_hash` imports `N_PARTIES` from here (which only depends on the leaf',
      '// committee module), not from `configs::default`.',
      '',
      '/// Number of registered parties (matches on-chain `topNodes` length).',
      `pub global N_PARTIES: u32 = crate::configs::committee::${committee}::N_PARTIES;`,
      '/// Secret-sharing reconstruction threshold.',
      `pub global T: u32 = crate::configs::committee::${committee}::T;`,
      '/// Honest-party count expected during the DKG (`H <= N_PARTIES`).',
      `pub global H: u32 = crate::configs::committee::${committee}::H;`,
      '',
      '/// Parity matrices for the secret-sharing scheme, sized for the active committee.',
      '/// `configs::{insecure,secure}::dkg` re-exports the relevant one as `PARITY_MATRIX`.',
      `pub use crate::configs::committee::${committee}::parity_insecure::PARITY_MATRIX as PARITY_MATRIX_INSECURE;`,
      `pub use crate::configs::committee::${committee}::parity_secure::PARITY_MATRIX as PARITY_MATRIX_SECURE;`,
      '',
    ].join('\n')
    writeFileSync(activeNrPath, content)
    console.log(`   📋 Set Noir committee to: ${committee}`)
  }

  /**
   * Regenerates `circuits/lib/src/configs/committee/<committee>/parity_{insecure,secure}.nr`
   * by invoking the Rust `generate_parity_matrices` binary. The Reed-Solomon parity matrix is
   * a deterministic function of `(N, T, QIS)` — committing the output keeps `nargo check`
   * working standalone, but the build script always overwrites it so a change in committee
   * or BFV preset constants can never silently desync the on-disk literal from what the
   * prover would compute at witness time.
   */
  private regenerateParityMatrices(committee: CircuitCommittee): void {
    const libDir = join(this.rootDir, 'circuits', 'lib')
    try {
      execSync(`cargo run --quiet --release --bin generate_parity_matrices -- --committee ${committee}`, {
        cwd: this.rootDir,
        stdio: ['ignore', 'pipe', 'inherit'],
      })
      execSync('nargo fmt', { cwd: libDir, stdio: ['ignore', 'pipe', 'inherit'] })
      console.log(`   📋 Regenerated parity_{insecure,secure}.nr for committee: ${committee}`)
    } catch (err: any) {
      throw new Error(
        `Failed to regenerate parity matrices for committee=${committee}: ${err.message}\n` +
          `   Try: cargo run --release --bin generate_parity_matrices -- --committee ${committee}`,
      )
    }
  }

  /**
   * Patch `packages/interfold-contracts/scripts/utils.ts` so `BFV_DKG_H` and `BFV_THRESHOLD_T`
   * track the active committee. The gas-benchmark and verifier-deploy scripts pull from this
   * file at runtime, so any mismatch between the compiled circuit and the deployed verifier
   * surfaces as `InvalidPublicInputsLength()` on-chain.
   */
  private patchUtilsTs(committee: CircuitCommittee): void {
    if (this.options.skipUtilsPatch) return
    const { h, t, n } = COMMITTEE_PARAMS[committee]
    const path = join(this.rootDir, 'packages', 'interfold-contracts', 'scripts', 'utils.ts')
    if (!existsSync(path)) return // optional in minimal checkouts
    const before = readFileSync(path, 'utf-8')
    const cap = committee.charAt(0).toUpperCase() + committee.slice(1)
    const generatedDoc = `/**
 * <generated-committee-doc>
 * Default insecure-512 / ${committee} committee layout for BFV aggregator verifiers.
 * Must match \`lib::configs::default::{H, T}\` in compiled circuits.
 * ${cap} committee: N=${n}, T=${t}, H=${h}.
 * </generated-committee-doc>
 */`
    const docPattern = /\/\*\*\s*\n \* <generated-committee-doc>[\s\S]*?<\/generated-committee-doc>\s*\n \*\//

    let after = before
      .replace(/export const BFV_DKG_H = \d+/, `export const BFV_DKG_H = ${h}`)
      .replace(/export const BFV_THRESHOLD_T = \d+/, `export const BFV_THRESHOLD_T = ${t}`)

    if (!after.includes(`export const BFV_DKG_H = ${h}`)) {
      throw new Error(`patchUtilsTs: could not update BFV_DKG_H in ${path} (expected export const BFV_DKG_H = <number>)`)
    }
    if (!after.includes(`export const BFV_THRESHOLD_T = ${t}`)) {
      throw new Error(`patchUtilsTs: could not update BFV_THRESHOLD_T in ${path} (expected export const BFV_THRESHOLD_T = <number>)`)
    }

    if (!docPattern.test(before)) {
      throw new Error(
        `patchUtilsTs: ${path} is missing the <generated-committee-doc> sentinel block; ` +
          `add the sentinel comment (see scripts/build-circuits.ts) so committee docs stay in sync`,
      )
    }
    const afterDoc = after.replace(docPattern, generatedDoc)
    if (afterDoc === after) {
      console.warn(`   ⚠️  patchUtilsTs: <generated-committee-doc> block in ${path} did not change (committee=${committee})`)
    }
    after = afterDoc

    if (after !== before) {
      writeFileSync(path, after)
      console.log(`   📋 Patched utils.ts: BFV_DKG_H=${h}, BFV_THRESHOLD_T=${t} (committee: ${committee})`)
    }
  }

  private presetStampPath(preset: string, committee: string): string {
    return join(this.options.outputDir!, preset, committee, '.build-stamp.json')
  }

  private readPresetStamp(preset: string, committee: string): PresetBuildStamp | null {
    const stampPath = this.presetStampPath(preset, committee)
    if (!existsSync(stampPath)) return null
    try {
      return JSON.parse(readFileSync(stampPath, 'utf-8')) as PresetBuildStamp
    } catch {
      return null
    }
  }

  private writePresetStamp(preset: string, committee: string, sourceHash: string): void {
    const stamp: PresetBuildStamp = {
      preset,
      committee: committee as CircuitCommittee,
      sourceHash,
      builtAt: new Date().toISOString(),
    }
    mkdirSync(join(this.options.outputDir!, preset, committee), { recursive: true })
    writeFileSync(this.presetStampPath(preset, committee), JSON.stringify(stamp, null, 2) + '\n')
  }

  /**
   * Records which BFV preset + committee last populated `circuits/bin/`. Read by:
   * - the benchmark gas-extraction pipeline (`scripts/benchmarkGasFromRaw.ts`)
   * - the Rust integration tests (cross-checked against `INTERFOLD_COMMITTEE_SIZE`).
   * A drift between this stamp and what the consumer expects fails fast.
   */
  private writeActiveBinPresetStamp(preset: string, sourceHash: string): void {
    const stamp: PresetBuildStamp = {
      preset,
      // Narrow out 'all': this runs per resolved preset/committee, so 'all' is meaningless here
      // and must never be persisted into the stamp that --skip-if-built later compares against.
      committee: this.options.committee === 'all' ? undefined : this.options.committee,
      sourceHash,
      builtAt: new Date().toISOString(),
    }
    writeFileSync(join(this.circuitsDir, '.active-preset.json'), JSON.stringify(stamp, null, 2) + '\n')
  }

  /**
   * Point circuits/bin at a preset already archived under dist/circuits/<preset>/.
   * Used when dist is fresh but bin still holds another preset (common after --mode insecure
   * then --mode secure benchmark runs).
   */
  private hydrateBinFromDist(preset: string, committee: string, sourceHash: string): void {
    const distRoot = join(this.options.outputDir!, preset, committee)
    const circuits = this.discoverCircuits()
    let copied = 0

    for (const circuit of circuits) {
      const packageName = this.getPackageName(circuit.path)
      const targetDir = join(circuit.path, 'target')
      mkdirSync(targetDir, { recursive: true })

      const copyPair = (from: string, to: string) => {
        if (!existsSync(from)) return
        copyFileSync(from, to)
        copied++
      }

      const defaultDir = join(distRoot, CIRCUIT_VARIANTS.DEFAULT, circuit.group, circuit.name)
      copyPair(join(defaultDir, `${packageName}.json`), join(targetDir, `${packageName}.json`))
      copyPair(join(defaultDir, `${packageName}.vk`), join(targetDir, `${packageName}.vk_recursive`))
      copyPair(join(defaultDir, `${packageName}.vk_hash`), join(targetDir, `${packageName}.vk_recursive_hash`))

      const evmDir = join(distRoot, CIRCUIT_VARIANTS.EVM, circuit.group, circuit.name)
      copyPair(join(evmDir, `${packageName}.vk`), join(targetDir, `${packageName}.vk`))
      copyPair(join(evmDir, `${packageName}.vk_hash`), join(targetDir, `${packageName}.vk_hash`))

      const recursiveDir = join(distRoot, CIRCUIT_VARIANTS.RECURSIVE, circuit.group, circuit.name)
      copyPair(join(recursiveDir, `${packageName}.vk`), join(targetDir, `${packageName}.vk_noir`))
      copyPair(join(recursiveDir, `${packageName}.vk_hash`), join(targetDir, `${packageName}.vk_noir_hash`))
    }

    console.log(`   Copied ${copied} artifact file(s) into circuits/bin targets.`)
    this.writeActiveBinPresetStamp(preset, sourceHash)
  }

  private requiredDistMarkers(preset: string, committee: string): string[] {
    const dist = join(this.options.outputDir!, preset, committee)
    return [
      join(dist, CIRCUIT_VARIANTS.DEFAULT, CIRCUIT_GROUPS.AGGREGATION, 'dkg_aggregator', 'dkg_aggregator.json'),
      join(dist, CIRCUIT_VARIANTS.DEFAULT, CIRCUIT_GROUPS.AGGREGATION, 'decryption_aggregator', 'decryption_aggregator.json'),
    ]
  }

  /** Marker files required by `test_trbfv_actor` / gas extraction under circuits/bin. */
  private requiredBinMarkers(): string[] {
    const bin = this.circuitsDir
    return [
      join(bin, CIRCUIT_GROUPS.AGGREGATION, 'dkg_aggregator', 'target', 'dkg_aggregator.json'),
      join(bin, CIRCUIT_GROUPS.AGGREGATION, 'dkg_aggregator', 'target', 'dkg_aggregator.vk_recursive'),
      join(bin, CIRCUIT_GROUPS.AGGREGATION, 'decryption_aggregator', 'target', 'decryption_aggregator.json'),
      join(bin, CIRCUIT_GROUPS.AGGREGATION, 'decryption_aggregator', 'target', 'decryption_aggregator.vk_recursive'),
      join(bin, CIRCUIT_GROUPS.DKG, 'target', 'pk.json'),
      join(bin, CIRCUIT_GROUPS.THRESHOLD, 'target', 'pk_aggregation.json'),
    ]
  }

  private readActiveBinPreset(): PresetBuildStamp | null {
    const activePath = join(this.circuitsDir, '.active-preset.json')
    if (!existsSync(activePath)) return null
    try {
      return JSON.parse(readFileSync(activePath, 'utf-8')) as PresetBuildStamp
    } catch {
      return null
    }
  }

  private isDistPresetUpToDate(preset: string, committee: string, sourceHash: string): boolean {
    const stamp = this.readPresetStamp(preset, committee)
    if (!stamp?.sourceHash || stamp.sourceHash !== sourceHash) return false
    return this.requiredDistMarkers(preset, committee).every((path) => existsSync(path))
  }

  private isBinReadyForPreset(preset: string, committee: string, sourceHash: string): boolean {
    const active = this.readActiveBinPreset()
    if (!active || active.preset !== preset || active.sourceHash !== sourceHash) return false
    if (active.committee && active.committee !== committee) return false
    return this.requiredBinMarkers().every((path) => existsSync(path))
  }

  private isPresetUpToDate(preset: string, committee: string, sourceHash: string): boolean {
    return this.isDistPresetUpToDate(preset, committee, sourceHash) && this.isBinReadyForPreset(preset, committee, sourceHash)
  }

  private logSkipIfBuiltBlocked(preset: string, committee: string, sourceHash: string): void {
    const stamp = this.readPresetStamp(preset, committee)
    const stampPath = this.presetStampPath(preset, committee)
    if (!stamp?.sourceHash) {
      console.log(`   ℹ️  --skip-if-built: no stamp at ${stampPath}`)
      return
    }
    if (stamp.sourceHash !== sourceHash) {
      console.log(
        `   ℹ️  --skip-if-built: circuit sources changed (stamp ${stamp.sourceHash} → ${sourceHash}). ` +
          `Run without --skip-if-built or \`pnpm build:circuits --preset ${preset}\` once to refresh.`,
      )
    }
    const missing = [...this.requiredDistMarkers(preset, committee), ...this.requiredBinMarkers()].filter((path) => !existsSync(path))
    if (missing.length > 0) {
      console.log(`   ℹ️  --skip-if-built: missing ${missing.length} marker artifact(s), e.g. ${missing[0]}`)
    }
  }

  /**
   * Writes preset + committee selection to the persistent Noir/TS config files so they stay
   * aligned with `circuits/bin/.active-preset.json` even on hydrate-only or skip-if-built paths.
   */
  private syncPresetAndCommittee(modNrPath: string, preset: CircuitPreset, committee?: CircuitCommittee): void {
    this.setNoirConfigPreset(modNrPath, preset)
    if (committee) {
      this.setNoirCommittee(committee)
      this.regenerateParityMatrices(committee)
      this.patchUtilsTs(committee)
    }
  }

  private async buildForPreset(preset: CircuitPreset, committee: CircuitCommittee, modNrPath?: string): Promise<BuildResult> {
    const result: BuildResult = { success: true, compiled: [], errors: [] }
    const presetOutputDir = join(this.options.outputDir!, preset, committee)

    console.log(`\n🔮 Building preset: ${preset}, committee: ${committee}...`)

    try {
      this.checkTool('nargo --version', 'nargo')
      if (!this.options.skipVk) this.checkTool('bb --version', 'bb')

      const circuits = this.discoverCircuits()
      if (circuits.length === 0) {
        console.log('   ⚠️  No circuits found')
        return result
      }

      console.log(`   Found ${circuits.length} circuit(s)`)

      if (this.options.dryRun) {
        console.log('\n   Would build:', circuits.map((c) => `${c.group}/${c.name}`).join(', '))
        return result
      }

      const sourceHash = this.computeSourceHash(preset)
      result.sourceHash = sourceHash

      if (modNrPath) {
        this.syncPresetAndCommittee(modNrPath, preset, committee)
      }

      if (this.options.hydrateBinOnly) {
        if (!this.isDistPresetUpToDate(preset, committee, sourceHash)) {
          throw new Error(
            `Cannot hydrate circuits/bin: dist/circuits/${preset}/${committee} is missing or stale. ` +
              `Run: pnpm build:circuits --preset ${preset} --committee ${committee}`,
          )
        }
        console.log(`   💧 Hydrating circuits/bin from dist/circuits/${preset}/${committee} (no nargo compile)...`)
        this.hydrateBinFromDist(preset, committee, sourceHash)
        console.log(`\n✅ Hydrated circuits/bin for preset: ${preset}/${committee}`)
        return result
      }

      if (this.options.skipIfBuilt) {
        if (this.isPresetUpToDate(preset, committee, sourceHash)) {
          console.log(
            `   ⏭️  Skipping preset ${preset}/${committee} (dist + circuits/bin up to date; source_hash=${sourceHash}). ` +
              `Use a full rebuild without --skip-if-built to refresh.`,
          )
          return result
        }
        if (this.isDistPresetUpToDate(preset, committee, sourceHash)) {
          console.log(
            `   💧 dist/circuits/${preset}/${committee} is current; hydrating circuits/bin from dist ` +
              `(fast — avoids a full ~50m secure recompile when switching presets).`,
          )
          this.hydrateBinFromDist(preset, committee, sourceHash)
          console.log(`\n✅ Hydrated circuits/bin for preset: ${preset}/${committee}`)
          return result
        }
        this.logSkipIfBuiltBlocked(preset, committee, sourceHash)
      }

      if (!this.options.noCleanTargets) {
        this.cleanTargetDirs(circuits)
      }
      mkdirSync(presetOutputDir, { recursive: true })

      for (const circuit of circuits) {
        try {
          result.compiled.push(this.buildCircuit(circuit, preset, committee))
        } catch (error: any) {
          result.errors.push(`${preset}/${committee}/${circuit.name}: ${error.message}`)
          result.success = false
        }
      }

      this.copyArtifacts(result.compiled, presetOutputDir, preset)
      if (result.errors.length === 0) {
        this.writePresetStamp(preset, committee, sourceHash)
        this.writeActiveBinPresetStamp(preset, sourceHash)
      }
      console.log(`\n✅ Built ${result.compiled.length} circuits for preset: ${preset}/${committee}`)
      if (result.errors.length > 0) {
        console.error('\n❌ Failed circuits:')
        for (const err of result.errors) console.error(`   ${err}`)
      }
    } catch (error: any) {
      result.success = false
      result.errors.push(error.message)
      console.error('❌ Error:', error.message)
    }

    return result
  }

  private checkTool(cmd: string, name: string): void {
    try {
      execSync(cmd, { stdio: ['pipe', 'pipe', 'pipe'] })
    } catch {
      throw new Error(`${name} is not installed or not in PATH`)
    }
  }

  private cleanTargetDirs(circuits: CircuitInfo[]): void {
    const cleaned = new Set<string>()
    for (const circuit of circuits) {
      // Clean group-level target (e.g. circuits/bin/dkg/target)
      const groupTarget = join(this.circuitsDir, circuit.group, 'target')
      if (!cleaned.has(groupTarget) && existsSync(groupTarget)) {
        rmSync(groupTarget, { recursive: true })
        cleaned.add(groupTarget)
      }
      // Clean circuit-level target (e.g. circuits/bin/dkg/pk/target)
      const circuitTarget = join(circuit.path, 'target')
      if (!cleaned.has(circuitTarget) && existsSync(circuitTarget)) {
        rmSync(circuitTarget, { recursive: true })
        cleaned.add(circuitTarget)
      }
    }
    // Clean root-level target (circuits/bin/target)
    const rootTarget = join(this.circuitsDir, 'target')
    if (existsSync(rootTarget)) {
      rmSync(rootTarget, { recursive: true })
      cleaned.add(rootTarget)
    }
    if (cleaned.size > 0) {
      console.log(`   🧹 Cleaned ${cleaned.size} stale target dir(s)`)
    }
  }

  private discoverCircuits(): CircuitInfo[] {
    const circuits: CircuitInfo[] = []
    if (!existsSync(this.circuitsDir)) return circuits

    for (const group of this.options.groups ?? ALL_GROUPS) {
      const groupDir = join(this.circuitsDir, group)
      if (!existsSync(groupDir)) continue

      this.findCircuitsInDir(groupDir, '', group, circuits)
    }
    return circuits
  }

  private findCircuitsInDir(dir: string, relativePath: string, group: CircuitGroup, out: CircuitInfo[]): void {
    for (const entry of readdirSync(dir)) {
      const fullPath = join(dir, entry)
      if (!statSync(fullPath).isDirectory()) continue

      const name = relativePath ? `${relativePath}/${entry}` : entry
      const nargoPath = join(fullPath, 'Nargo.toml')
      if (!existsSync(nargoPath)) {
        this.findCircuitsInDir(fullPath, name, group, out)
        continue
      }
      // Workspace roots ([workspace]) are not circuits; recurse to find leaf packages
      if (this.isWorkspaceOnly(nargoPath)) {
        this.findCircuitsInDir(fullPath, name, group, out)
      } else if (!this.options.circuits || this.options.circuits.includes(name)) {
        out.push({ name, group, path: fullPath })
      }
    }
  }

  private isWorkspaceOnly(nargoPath: string): boolean {
    const content = readFileSync(nargoPath, 'utf-8')
    return /^\s*\[workspace\]/m.test(content) && !/^\s*\[package\]/m.test(content)
  }

  /** Search dirs for compiled JSON; include parent targets (workspace members output to workspace root). */
  private getTargetSearchDirs(circuitPath: string, groupDir: string): string[] {
    const dirs = [join(circuitPath, 'target')]
    let dir = circuitPath
    while (dir !== groupDir) {
      const parent = resolve(dir, '..')
      if (parent === dir) break
      dirs.push(join(parent, 'target'))
      dir = parent
    }
    dirs.push(join(groupDir, 'target'), join(this.circuitsDir, 'target'))
    return dirs
  }

  private buildCircuit(circuit: CircuitInfo, preset: string, committee: CircuitCommittee): CompiledCircuit {
    const packageName = this.getPackageName(circuit.path)
    const result: CompiledCircuit = {
      name: circuit.name,
      group: circuit.group,
      preset,
      committee,
      artifacts: {},
      checksums: {},
    }

    execSync('nargo compile', { cwd: circuit.path, stdio: 'pipe' })

    const groupDir = join(this.circuitsDir, circuit.group)
    const targetDirs = this.getTargetSearchDirs(circuit.path, groupDir)

    let jsonFile: string | null = null
    let targetDir: string | null = null

    for (const dir of targetDirs) {
      if (!existsSync(dir)) continue
      const candidate = join(dir, `${packageName}.json`)
      if (existsSync(candidate)) {
        jsonFile = candidate
        targetDir = dir
        break
      }
    }

    if (!jsonFile || !targetDir) {
      throw new Error(
        `${circuit.group}/${circuit.name}: compiled artifact not found. ` + `Searched for ${packageName}.json in: ${targetDirs.join(', ')}`,
      )
    }

    this.sanitizePaths(jsonFile)
    result.artifacts.json = jsonFile
    result.checksums.json = this.checksum(jsonFile)

    if (!this.options.skipVk) {
      const vkArtifacts = this.generateVk(circuit, jsonFile, targetDir, packageName)
      if (vkArtifacts.vk) {
        result.artifacts.vk = vkArtifacts.vk
        result.checksums.vk = this.checksum(vkArtifacts.vk)
      }
      if (vkArtifacts.vkHash && existsSync(vkArtifacts.vkHash)) {
        result.artifacts.vkHash = vkArtifacts.vkHash
        result.checksums.vkHash = this.checksum(vkArtifacts.vkHash)
      }
      if (vkArtifacts.vkRecursive) {
        result.artifacts.vkRecursive = vkArtifacts.vkRecursive
        result.checksums.vkRecursive = this.checksum(vkArtifacts.vkRecursive)
      }
      if (vkArtifacts.vkRecursiveHash && existsSync(vkArtifacts.vkRecursiveHash)) {
        result.artifacts.vkRecursiveHash = vkArtifacts.vkRecursiveHash
        result.checksums.vkRecursiveHash = this.checksum(vkArtifacts.vkRecursiveHash)
      }
      if (vkArtifacts.vkNoir) {
        result.artifacts.vkNoir = vkArtifacts.vkNoir
        result.checksums.vkNoir = this.checksum(vkArtifacts.vkNoir)
      }
      if (vkArtifacts.vkNoirHash && existsSync(vkArtifacts.vkNoirHash)) {
        result.artifacts.vkNoirHash = vkArtifacts.vkNoirHash
        result.checksums.vkNoirHash = this.checksum(vkArtifacts.vkNoirHash)
      }
    }
    console.log(`   ✓ ${circuit.group}/${circuit.name}`)

    return result
  }

  private isFoldOrAggregation(circuit: CircuitInfo): boolean {
    return circuit.group === CIRCUIT_GROUPS.AGGREGATION
  }

  /** Aggregation circuits that are also published on-chain as EVM verifiable proofs. */
  private isAggregationWithEvmOnChain(circuit: CircuitInfo): boolean {
    if (circuit.group !== CIRCUIT_GROUPS.AGGREGATION) return false
    const name = basename(circuit.path)
    return name === 'dkg_aggregator' || name === 'decryption_aggregator'
  }

  private generateVk(
    circuit: CircuitInfo,
    jsonFile: string,
    targetDir: string,
    packageName: string,
  ): {
    vk: string | null
    vkHash: string | null
    vkRecursive: string | null
    vkRecursiveHash: string | null
    vkNoir: string | null
    vkNoirHash: string | null
  } {
    const result = {
      vk: null as string | null,
      vkHash: null as string | null,
      vkRecursive: null as string | null,
      vkRecursiveHash: null as string | null,
      vkNoir: null as string | null,
      vkNoirHash: null as string | null,
    }
    const isFoldOrAggregation = this.isFoldOrAggregation(circuit)

    const runWriteVk = (verifierTarget: string, vkOut: string, vkHashOut: string): boolean => {
      try {
        execSync(`bb write_vk -b "${jsonFile}" -o "${targetDir}" -t ${verifierTarget}`, { stdio: 'pipe' })
        const defaultVk = join(targetDir, 'vk')
        const defaultVkHash = join(targetDir, 'vk_hash')
        if (!existsSync(defaultVk) || !existsSync(defaultVkHash)) {
          console.error(
            `VK artifacts missing after bb write_vk (${verifierTarget}) for ${jsonFile}: expected ${defaultVk} and ${defaultVkHash}`,
          )
          return false
        }
        if (existsSync(vkOut)) rmSync(vkOut)
        copyFileSync(defaultVk, vkOut)
        rmSync(defaultVk)
        if (existsSync(vkHashOut)) rmSync(vkHashOut)
        copyFileSync(defaultVkHash, vkHashOut)
        rmSync(defaultVkHash)
        return true
      } catch (err) {
        console.error(`Error generating VK (${verifierTarget}) for ${jsonFile}:`, err)
        return false
      }
    }

    const vkFile = join(targetDir, `${packageName}.vk`)
    const vkHashFile = join(targetDir, `${packageName}.vk_hash`)
    const vkRecursiveFile = join(targetDir, `${packageName}.vk_recursive`)
    const vkRecursiveHashFile = join(targetDir, `${packageName}.vk_recursive_hash`)
    const vkNoirFile = join(targetDir, `${packageName}.vk_noir`)
    const vkNoirHashFile = join(targetDir, `${packageName}.vk_noir_hash`)

    if (isFoldOrAggregation) {
      // Aggregation fold circuits: Default variant (noir-recursive-no-zk) for witness generation.
      if (!runWriteVk('noir-recursive-no-zk', vkRecursiveFile, vkRecursiveHashFile)) {
        throw new Error(`VK generation failed for ${packageName} (noir-recursive-no-zk)`)
      }
      result.vkRecursive = existsSync(vkRecursiveFile) ? vkRecursiveFile : null
      result.vkRecursiveHash = existsSync(vkRecursiveHashFile) ? vkRecursiveHashFile : null

      // DKG / decryption aggregators are additionally proven with `-t evm` for on-chain verification.
      if (this.isAggregationWithEvmOnChain(circuit)) {
        if (!runWriteVk('evm', vkFile, vkHashFile)) {
          throw new Error(`VK generation failed for ${packageName} (evm)`)
        }
        result.vk = existsSync(vkFile) ? vkFile : null
        result.vkHash = existsSync(vkHashFile) ? vkHashFile : null
      }
    } else {
      // Base DKG/threshold circuits: evm + noir-recursive-no-zk + noir-recursive
      if (!runWriteVk('evm', vkFile, vkHashFile)) {
        throw new Error(`VK generation failed for ${packageName} (evm)`)
      }
      result.vk = existsSync(vkFile) ? vkFile : null
      result.vkHash = existsSync(vkHashFile) ? vkHashFile : null

      if (!runWriteVk('noir-recursive-no-zk', vkRecursiveFile, vkRecursiveHashFile)) {
        throw new Error(`VK generation failed for ${packageName} (noir-recursive-no-zk)`)
      }
      result.vkRecursive = existsSync(vkRecursiveFile) ? vkRecursiveFile : null
      result.vkRecursiveHash = existsSync(vkRecursiveHashFile) ? vkRecursiveHashFile : null

      if (!runWriteVk('noir-recursive', vkNoirFile, vkNoirHashFile)) {
        throw new Error(`VK generation failed for ${packageName} (noir-recursive)`)
      }
      result.vkNoir = existsSync(vkNoirFile) ? vkNoirFile : null
      result.vkNoirHash = existsSync(vkNoirHashFile) ? vkNoirHashFile : null
    }

    return result
  }

  private getPackageName(circuitPath: string): string {
    try {
      const content = readFileSync(join(circuitPath, 'Nargo.toml'), 'utf-8')
      const match = content.match(/^name\s*=\s*"([^"]+)"/m)
      if (match) return match[1]
    } catch {
      // Ignore errors
    }
    return basename(circuitPath)
  }

  private sanitizePaths(jsonFile: string): void {
    try {
      const content = readFileSync(jsonFile, 'utf-8')
      const sanitized = content
        .replace(/"path"\s*:\s*"[^"]*[/\\](interfold[/\\]circuits[/\\][^"]+)"/g, '"path":"$1"')
        .replace(/"path"\s*:\s*"(?:\/[^"]*|[A-Za-z]:\\[^"]*)[/\\](circuits[/\\][^"]+)"/g, '"path":"interfold/$1"')
      if (content !== sanitized) writeFileSync(jsonFile, sanitized)
    } catch {
      // Ignore errors
    }
  }

  private checksum(filePath: string): string {
    return createHash('sha256').update(readFileSync(filePath)).digest('hex')
  }

  private generateChecksumFile(compiled: CompiledCircuit[]): string {
    const lines: string[] = []
    const checksums: Record<string, string> = {}

    for (const c of compiled) {
      const packageName = basename(c.artifacts.json ?? '', '.json')

      // evm/ variant checksums (only for circuits that have an evm VK)
      if (c.checksums.vk && c.artifacts.vk) {
        const evmPrefix = `${c.preset}/${c.committee}/${CIRCUIT_VARIANTS.EVM}/${c.group}/${c.name}`
        if (c.checksums.json && c.artifacts.json) {
          const f = `${evmPrefix}/${basename(c.artifacts.json)}`
          checksums[f] = c.checksums.json
          lines.push(`${c.checksums.json}  ${f}`)
        }
        const f = `${evmPrefix}/${basename(c.artifacts.vk)}`
        checksums[f] = c.checksums.vk
        lines.push(`${c.checksums.vk}  ${f}`)
        if (c.checksums.vkHash && c.artifacts.vkHash) {
          const fHash = `${evmPrefix}/${basename(c.artifacts.vkHash)}`
          checksums[fHash] = c.checksums.vkHash
          lines.push(`${c.checksums.vkHash}  ${fHash}`)
        }
      }

      // default/ variant checksums
      const defaultPrefix = `${c.preset}/${c.committee}/${CIRCUIT_VARIANTS.DEFAULT}/${c.group}/${c.name}`
      if (c.checksums.json && c.artifacts.json) {
        const f = `${defaultPrefix}/${basename(c.artifacts.json)}`
        checksums[f] = c.checksums.json
        lines.push(`${c.checksums.json}  ${f}`)
      }
      if (c.checksums.vkRecursive && c.artifacts.vkRecursive) {
        // In default/ variant, .vk_recursive is stored as .vk
        const f = `${defaultPrefix}/${packageName}.vk`
        checksums[f] = c.checksums.vkRecursive
        lines.push(`${c.checksums.vkRecursive}  ${f}`)
      }
      if (c.checksums.vkRecursiveHash && c.artifacts.vkRecursiveHash) {
        // In default/ variant, .vk_recursive_hash is stored as .vk_hash
        const f = `${defaultPrefix}/${packageName}.vk_hash`
        checksums[f] = c.checksums.vkRecursiveHash
        lines.push(`${c.checksums.vkRecursiveHash}  ${f}`)
      }
      // recursive/ variant checksums (noir-recursive VKs for inner proofs)
      if (c.checksums.vkNoir && c.artifacts.vkNoir) {
        const recursivePrefix = `${c.preset}/${c.committee}/${CIRCUIT_VARIANTS.RECURSIVE}/${c.group}/${c.name}`
        if (c.checksums.json && c.artifacts.json) {
          const f = `${recursivePrefix}/${basename(c.artifacts.json)}`
          checksums[f] = c.checksums.json
          lines.push(`${c.checksums.json}  ${f}`)
        }
        const fVk = `${recursivePrefix}/${packageName}.vk`
        checksums[fVk] = c.checksums.vkNoir
        lines.push(`${c.checksums.vkNoir}  ${fVk}`)
        if (c.checksums.vkNoirHash && c.artifacts.vkNoirHash) {
          const fHash = `${recursivePrefix}/${packageName}.vk_hash`
          checksums[fHash] = c.checksums.vkNoirHash
          lines.push(`${c.checksums.vkNoirHash}  ${fHash}`)
        }
      }
    }

    const outputDir = this.options.outputDir!
    writeFileSync(join(outputDir, 'SHA256SUMS'), lines.join('\n') + '\n')
    writeFileSync(
      join(outputDir, 'checksums.json'),
      JSON.stringify({ algorithm: 'sha256', generated: new Date().toISOString(), files: checksums }, null, 2) + '\n',
    )
    return join(outputDir, 'SHA256SUMS')
  }

  private copyArtifacts(compiled: CompiledCircuit[], outputDir: string, _preset: CircuitPreset | string): string {
    for (const c of compiled) {
      if (!c.artifacts.json && !c.artifacts.vk) continue
      const packageName = basename(c.artifacts.json ?? '', '.json')

      // Copy to evm/ variant: .json + evm .vk + .vk_hash (only for circuits that have an evm VK)
      if (c.artifacts.vk) {
        const evmDir = join(outputDir, CIRCUIT_VARIANTS.EVM, c.group, c.name)
        mkdirSync(evmDir, { recursive: true })
        if (c.artifacts.json) copyFileSync(c.artifacts.json, join(evmDir, basename(c.artifacts.json)))
        copyFileSync(c.artifacts.vk, join(evmDir, basename(c.artifacts.vk)))
        if (c.artifacts.vkHash) copyFileSync(c.artifacts.vkHash, join(evmDir, basename(c.artifacts.vkHash)))
      }

      // Copy to default/ variant: .json + noir-recursive-no-zk .vk (aggregation fold proofs)
      const defaultDir = join(outputDir, CIRCUIT_VARIANTS.DEFAULT, c.group, c.name)
      mkdirSync(defaultDir, { recursive: true })
      if (c.artifacts.json) copyFileSync(c.artifacts.json, join(defaultDir, basename(c.artifacts.json)))
      if (c.artifacts.vkRecursive) {
        copyFileSync(c.artifacts.vkRecursive, join(defaultDir, `${packageName}.vk`))
      }
      if (c.artifacts.vkRecursiveHash) {
        copyFileSync(c.artifacts.vkRecursiveHash, join(defaultDir, `${packageName}.vk_hash`))
      }

      // Copy to recursive/ variant: .json + noir-recursive .vk (inner/base proofs fed into wrapper)
      if (c.artifacts.vkNoir) {
        const recursiveDir = join(outputDir, CIRCUIT_VARIANTS.RECURSIVE, c.group, c.name)
        mkdirSync(recursiveDir, { recursive: true })
        if (c.artifacts.json) copyFileSync(c.artifacts.json, join(recursiveDir, basename(c.artifacts.json)))
        copyFileSync(c.artifacts.vkNoir, join(recursiveDir, `${packageName}.vk`))
        if (c.artifacts.vkNoirHash) {
          copyFileSync(c.artifacts.vkNoirHash, join(recursiveDir, `${packageName}.vk_hash`))
        }
      }
    }

    return outputDir
  }

  computeSourceHash(preset?: CircuitPreset): string {
    const hash = createHash('sha256')
    if (preset !== undefined) {
      hash.update(`preset:${preset}\n`)
      const tier = PRESET_NOIR_CONFIG[preset]
      hash.update(`noir_config:${tier}\n`)
      // Hash the contents of the preset's Noir config, not just its name: the baked crypto
      // constants (e.g. PK_GENERATION_E_SM_BOUND) live here and must invalidate --skip-if-built
      // when they change. Otherwise a bound update silently reuses a stale compiled circuit.
      const tierConfigDir = join(this.rootDir, 'circuits', 'lib', 'src', 'configs', tier)
      if (existsSync(tierConfigDir)) this.hashDir(tierConfigDir, hash)
    }
    if (this.options.committee) {
      hash.update(`committee:${this.options.committee}\n`)
    }
    const circuits = this.discoverCircuits().sort((a, b) => `${a.group}/${a.name}`.localeCompare(`${b.group}/${b.name}`))
    for (const c of circuits) this.hashDir(c.path, hash)
    return hash.digest('hex').substring(0, 16)
  }

  /** Generated at bench time; must not invalidate `--skip-if-built` between ensure passes. */
  private static readonly SKIP_SOURCE_HASH_ENTRIES = new Set(['target', 'Prover.toml', 'Witness.toml'])

  private hashDir(dirPath: string, hash: ReturnType<typeof createHash>, relativePath = ''): void {
    for (const entry of readdirSync(dirPath).sort()) {
      if (entry.startsWith('.') || NoirCircuitBuilder.SKIP_SOURCE_HASH_ENTRIES.has(entry)) continue
      const fullPath = join(dirPath, entry)
      const entryRelativePath = relativePath ? `${relativePath}/${entry}` : entry
      const stat = statSync(fullPath)
      if (stat.isDirectory()) {
        hash.update(entryRelativePath + '/')
        this.hashDir(fullPath, hash, entryRelativePath)
      } else if (stat.isFile()) {
        hash.update(entryRelativePath)
        hash.update(readFileSync(fullPath))
      }
    }
  }

  writeGitHubOutput(result: BuildResult): void {
    const output = process.env.GITHUB_OUTPUT
    const lines = [
      `circuits_built=${result.compiled.length}`,
      `circuits_success=${result.success}`,
      `source_hash=${result.sourceHash ?? 'unknown'}`,
      result.releaseDir ? `artifacts_dir=${result.releaseDir}` : '',
    ].filter(Boolean)

    if (output) appendFileSync(output, lines.join('\n') + '\n')
    else console.log('\n📋 CI Output:', lines.join(', '))
  }
}

// CLI
async function main() {
  const args = process.argv.slice(2)
  const options: BuildOptions = {}
  let command = 'build'

  for (let i = 0; i < args.length; i++) {
    const arg = args[i]
    if (arg === '-h' || arg === '--help') {
      showHelp()
      process.exit(0)
    } else if (arg === '--dry-run') options.dryRun = true
    else if (arg === '--skip-checksums') options.skipChecksums = true
    else if (arg === '--skip-vk') options.skipVk = true
    else if (arg === '--no-clean') options.clean = false
    else if (arg === '--no-clean-targets') options.noCleanTargets = true
    else if (arg === '--skip-if-built') options.skipIfBuilt = true
    else if (arg === '--hydrate-bin-only') options.hydrateBinOnly = true
    else if (arg === '--group') options.groups = args[++i]?.split(',') as CircuitGroup[]
    else if (arg === '--circuit') (options.circuits ??= []).push(args[++i])
    else if (arg === '-o' || arg === '--output') options.outputDir = resolve(args[++i])
    else if (arg === '--preset') {
      const val = args[++i]
      if (val !== 'all' && !ALL_PRESETS.includes(val as CircuitPreset)) {
        console.error(`Unknown preset: ${val}. Valid values: ${ALL_PRESETS.join(', ')}, all`)
        process.exit(1)
      }
      options.preset = val as CircuitPreset | 'all'
    } else if (arg === '--committee') {
      const val = args[++i]
      if (val !== 'all' && !ALL_COMMITTEES.includes(val as CircuitCommittee)) {
        console.error(`Unknown committee: ${val}. Valid values: ${ALL_COMMITTEES.join(', ')}, all`)
        process.exit(1)
      }
      options.committee = val as CircuitCommittee | 'all'
    } else if (arg === '--skip-utils-patch') options.skipUtilsPatch = true
    else if (['hash', 'build'].includes(arg)) command = arg
  }

  const builder = new NoirCircuitBuilder(undefined, options)

  if (command === 'hash') {
    const preset = options.preset === 'all' ? undefined : options.preset
    const hash = builder.computeSourceHash(preset)
    console.log(hash)
    if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `source_hash=${hash}\n`)
  } else {
    const result = await builder.buildAll()
    builder.writeGitHubOutput(result)
    process.exit(result.success ? 0 : 1)
  }
}

function showHelp() {
  console.log(`
Usage: build-circuits [command] [options]

Commands: build (default), hash

Options:
  --group <groups>    Circuit groups (comma-separated: dkg,threshold)
  --circuit <name>    Build specific circuit(s)
  --preset <preset>   Parameter preset: insecure-512 (default), secure-8192, or all
  --committee <name>  Committee size: minimum (default), micro, small, or all
  --skip-utils-patch  Don't rewrite BFV_DKG_H/T in packages/interfold-contracts/scripts/utils.ts
  --skip-vk           Skip verification key generation
  --skip-checksums    Skip checksum generation
  -o, --output <dir>  Output directory (default: dist/circuits)
  --dry-run           Show what would be built
  --no-clean          Don't clean output directory
  --no-clean-targets  Don't delete circuits/bin target dirs before compiling
  --skip-if-built     Skip preset when dist + circuits/bin match; hydrate bin from dist if only dist is current
  --hydrate-bin-only  Copy dist/circuits/<preset>/ into circuits/bin (no nargo compile)
  -h, --help          Show help
`)
}

if (require.main === module) main()

export {
  NoirCircuitBuilder,
  BuildOptions,
  BuildResult,
  CompiledCircuit,
  CircuitInfo,
  CircuitGroup,
  CIRCUIT_GROUPS,
  CIRCUIT_PRESETS,
  type CircuitPreset,
}
