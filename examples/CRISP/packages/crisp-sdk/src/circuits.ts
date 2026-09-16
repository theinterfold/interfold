// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { CompiledCircuit } from '@noir-lang/noir_js'

/** BFV parameter sets the circuits can be compiled against. */
export type CircuitPreset = 'insecure' | 'secure-8192' | 'secure-16384'

/**
 * The circuits whose bytecode depends on the BFV preset.
 *
 * The aggregation circuits — `crisp_fold`, `crisp_onchain_fold`, and `user_data_encryption` — are
 * deliberately absent. Their parameters are proof and verification-key shaped (410/115 fields), not
 * polynomial shaped, so one compiled artifact serves all presets; the fold circuits assert
 * `chain_key_hash` against the insecure *or* the secure constant for exactly that reason. They ship
 * in the main entry point, which is why `verifyProof` works without a preset loaded.
 */
export type CircuitBundle = {
  readonly preset: CircuitPreset
  readonly crisp: CompiledCircuit
  readonly crispOnchain: CompiledCircuit
  readonly ct0ChunkMain: CompiledCircuit
  readonly ct0ChunkMainRoot: CompiledCircuit
  readonly ct0PkCtCommit: CompiledCircuit
  readonly ct0ChunkGamma: CompiledCircuit
  readonly ct0EvalChunkMain: CompiledCircuit
  readonly ct0EvalChunkMainRoot: CompiledCircuit
  readonly ct0EvalPkCt: CompiledCircuit
  readonly ct0EvalChunkIdentity: CompiledCircuit
  readonly userDataEncryptionCt0: CompiledCircuit
  readonly ct1ChunkMain: CompiledCircuit
  readonly ct1ChunkMainRoot: CompiledCircuit
  readonly ct1PkCtCommit: CompiledCircuit
  readonly ct1ChunkGamma: CompiledCircuit
  readonly ct1EvalChunkMain: CompiledCircuit
  readonly ct1EvalChunkMainRoot: CompiledCircuit
  readonly ct1EvalPkCt: CompiledCircuit
  readonly ct1EvalChunkIdentity: CompiledCircuit
  readonly userDataEncryptionCt1: CompiledCircuit
}

let registered: CircuitBundle | null = null

/**
 * Install the preset-bound circuits used by `generateProof`.
 *
 * The bundle is not bundled into the main entry point, because the secure artifacts are more
 * than an order of magnitude larger than the insecure ones. Load the preset selected by the
 * round from its subpath and register it before proving:
 *
 * ```ts
 * import { setCircuits } from '@crisp-e3/sdk'
 * import { loadCircuits } from '@crisp-e3/sdk/insecure'
 *
 * setCircuits(await loadCircuits())
 * ```
 */
export const setCircuits = (bundle: CircuitBundle): void => {
  registered = bundle
}

/** The registered bundle, or `null` when none has been installed yet. */
export const getRegisteredCircuits = (): CircuitBundle | null => registered

/** The preset currently installed, or `null` when none has been installed yet. */
export const registeredPreset = (): CircuitPreset | null => registered?.preset ?? null

/**
 * The registered bundle, throwing a directed error when nothing has been installed.
 *
 * Proving cannot fall back to a default preset: a ballot proved against the wrong parameters fails
 * on chain rather than locally, so guessing here would move the failure somewhere much harder to
 * read.
 */
export const requireCircuits = (): CircuitBundle => {
  if (!registered) {
    throw new Error(
      'No circuit preset registered. Import `loadCircuits` from "@crisp-e3/sdk/insecure", ' +
        '"@crisp-e3/sdk/secure-8192", or "@crisp-e3/sdk/secure-16384" and pass the result ' +
        'to `setCircuits()` before proving.',
    )
  }

  return registered
}
