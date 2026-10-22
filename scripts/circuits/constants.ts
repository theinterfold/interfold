// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import buildPairs from './build-pairs.json'
import { COMMITTEES } from '../../packages/interfold-contracts/bfv'

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
  INSECURE_64: 'insecure-64',
  SECURE_8192: 'secure-8192',
} as const

export type CircuitPreset = (typeof CIRCUIT_PRESETS)[keyof typeof CIRCUIT_PRESETS]

export const ALL_PRESETS: CircuitPreset[] = [CIRCUIT_PRESETS.INSECURE_64, CIRCUIT_PRESETS.SECURE_8192]

/**
 * Maps each preset to the Noir config module it re-exports from `circuits/lib/src/configs/default/mod.nr`.
 */
export const PRESET_NOIR_CONFIG: Record<CircuitPreset, 'insecure' | 'secure'> = {
  [CIRCUIT_PRESETS.INSECURE_64]: 'insecure',
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
 * Committee dimensions from the shared binding, used to deploy matching verifier layouts.
 */
export interface CommitteeParams {
  n: number
  t: number
  h: number
}

export const COMMITTEE_PARAMS: Record<CircuitCommittee, CommitteeParams> = {
  [CIRCUIT_COMMITTEES.MINIMUM]: { n: COMMITTEES.minimum.n, t: COMMITTEES.minimum.t, h: COMMITTEES.minimum.h },
  [CIRCUIT_COMMITTEES.MICRO]: { n: COMMITTEES.micro.n, t: COMMITTEES.micro.t, h: COMMITTEES.micro.h },
  [CIRCUIT_COMMITTEES.SMALL]: { n: COMMITTEES.small.n, t: COMMITTEES.small.t, h: COMMITTEES.small.h },
}

/** Build policy shared with the Rust circuit builder. Manifest order defines build order. */
export const SUPPORTED_PRESET_COMMITTEE_PAIRS: ReadonlyArray<{
  preset: CircuitPreset
  committee: CircuitCommittee
}> = (() => {
  if (buildPairs.length === 0) throw new Error('Circuit build policy contains no supported pairs')
  const seen = new Set<string>()
  return buildPairs.map((pair) => {
    const [preset, committee] = pair as [CircuitPreset, CircuitCommittee]
    if (pair.length !== 2 || !ALL_PRESETS.includes(preset) || !ALL_COMMITTEES.includes(committee)) {
      throw new Error(`Invalid circuit build pair: ${JSON.stringify(pair)}`)
    }
    const key = `${preset}/${committee}`
    if (seen.has(key)) throw new Error(`Duplicate circuit build pair: ${key}`)
    seen.add(key)
    return { preset, committee }
  })
})()

export function isPresetCommitteeSupported(preset: CircuitPreset, committee: CircuitCommittee): boolean {
  return SUPPORTED_PRESET_COMMITTEE_PAIRS.some((p) => p.preset === preset && p.committee === committee)
}
