// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * Shared constants for circuit groups used across build and verifier generation scripts.
 */

export const CIRCUIT_GROUPS = {
  DKG: 'dkg',
  THRESHOLD: 'threshold',
  AGGREGATION: 'recursive_aggregation',
} as const

export type CircuitGroup = (typeof CIRCUIT_GROUPS)[keyof typeof CIRCUIT_GROUPS]

export const ALL_GROUPS: CircuitGroup[] = [CIRCUIT_GROUPS.DKG, CIRCUIT_GROUPS.THRESHOLD, CIRCUIT_GROUPS.AGGREGATION]

/**
 * Circuit variants determine the hash oracle used for VK generation and proving.
 *
 * - `default`: Uses poseidon/noir-recursive-no-zk — wrapper & fold proofs (efficient, no ZK blinding).
 * - `recursive`: Uses poseidon/noir-recursive — inner/base proofs (ZK blinding preserved).
 * - `evm`: Uses keccak — for on-chain EVM-verifiable proofs.
 */
export const CIRCUIT_VARIANTS = {
  DEFAULT: 'default',
  RECURSIVE: 'recursive',
  EVM: 'evm',
} as const

export type CircuitVariant = (typeof CIRCUIT_VARIANTS)[keyof typeof CIRCUIT_VARIANTS]

export const ALL_VARIANTS: CircuitVariant[] = [CIRCUIT_VARIANTS.DEFAULT, CIRCUIT_VARIANTS.RECURSIVE, CIRCUIT_VARIANTS.EVM]

/**
 * Circuit parameter presets identify which BFV parameter set the circuits were compiled for.
 * Named as `{security_tier}-{degree}`. Threshold and DKG presets at the same degree share
 * the same compiled circuit artifacts.
 */
export const CIRCUIT_PRESETS = {
  INSECURE_512: 'insecure-512',
  SECURE_8192: 'secure-8192',
} as const

export type CircuitPreset = (typeof CIRCUIT_PRESETS)[keyof typeof CIRCUIT_PRESETS]

export const ALL_PRESETS: CircuitPreset[] = [CIRCUIT_PRESETS.INSECURE_512, CIRCUIT_PRESETS.SECURE_8192]

/**
 * Maps each preset to the Noir config module it re-exports from `circuits/lib/src/configs/default/mod.nr`.
 */
export const PRESET_NOIR_CONFIG: Record<CircuitPreset, 'insecure' | 'secure'> = {
  [CIRCUIT_PRESETS.INSECURE_512]: 'insecure',
  [CIRCUIT_PRESETS.SECURE_8192]: 'secure',
}

/**
 * Committee sizes (matches Rust `CiphernodesCommitteeSize`). Selects the active
 * leaf module under `circuits/lib/src/configs/committee/{name}/` that `committee::active`
 * re-exports from. The wrapper Solidity verifiers (`BfvPkVerifier`, `BfvDecryptionVerifier`)
 * must be deployed with `H` and `T` matching the active selection.
 */
export const CIRCUIT_COMMITTEES = {
  MINIMUM: 'minimum',
  MICRO: 'micro',
  SMALL: 'small',
} as const

export type CircuitCommittee = (typeof CIRCUIT_COMMITTEES)[keyof typeof CIRCUIT_COMMITTEES]

export const ALL_COMMITTEES: CircuitCommittee[] = [CIRCUIT_COMMITTEES.MINIMUM, CIRCUIT_COMMITTEES.MICRO, CIRCUIT_COMMITTEES.SMALL]

/**
 * `(N, T, H)` per committee. Mirrors `circuits/lib/src/configs/committee/{name}/mod.nr`
 * and Rust `e3_zk_helpers::CiphernodesCommitteeSize::values()`. The build script writes
 * `H` and `T` into `packages/interfold-contracts/scripts/utils.ts` so the EVM gas benchmark
 * deploys verifiers with the matching public-input layout.
 */
export interface CommitteeParams {
  n: number
  t: number
  h: number
}

export const COMMITTEE_PARAMS: Record<CircuitCommittee, CommitteeParams> = {
  [CIRCUIT_COMMITTEES.MINIMUM]: { n: 3, t: 1, h: 2 },
  [CIRCUIT_COMMITTEES.MICRO]: { n: 9, t: 4, h: 5 },
  [CIRCUIT_COMMITTEES.SMALL]: { n: 19, t: 9, h: 10 },
}

/**
 * Every `(preset, committee)` pair is supported because the parity matrices are now regenerated
 * automatically from the BFV preset's `QIS` and the committee's `(N, T)` by the
 * `generate_parity_matrices` Rust binary, invoked from `scripts/build-circuits.ts` whenever
 * the committee is set. The matrix files on disk are derived artifacts, not hand-tuned data.
 *
 * This constant is kept for future use (e.g. if a particular pair is ever known-broken at
 * a higher level than the parity matrix) and currently returns the full Cartesian product.
 */
export const SUPPORTED_PRESET_COMMITTEE_PAIRS: ReadonlyArray<{
  preset: CircuitPreset
  committee: CircuitCommittee
}> = ALL_PRESETS.flatMap((preset) => ALL_COMMITTEES.map((committee) => ({ preset, committee })))

export function isPresetCommitteeSupported(preset: CircuitPreset, committee: CircuitCommittee): boolean {
  return SUPPORTED_PRESET_COMMITTEE_PAIRS.some((p) => p.preset === preset && p.committee === committee)
}
