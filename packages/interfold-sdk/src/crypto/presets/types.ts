// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { CompiledCircuit } from '@noir-lang/noir_js'

/** A recursive verification key, as bb.js `generateRecursiveProofArtifacts` returns it. */
export type RecursiveVk = { vkAsFields: string[]; vkHash: string }

type ProofTreeCircuit =
  | 'ct0ChunkMain'
  | 'ct0PkCtCommit'
  | 'ct0EvalChunkIdentity'
  | 'userDataEncryptionCt0'
  | 'ct1ChunkMain'
  | 'ct1PkCtCommit'
  | 'ct1EvalChunkIdentity'
  | 'userDataEncryptionCt1'

export type UserDataEncryptionProofBundle = Record<ProofTreeCircuit, CompiledCircuit> & {
  userDataEncryption: CompiledCircuit
  /**
   * Each tree circuit's recursive key, staged with its bytecode by `scripts/compile-circuits.sh`.
   * The prover uses these instead of rebuilding every circuit to return its key.
   */
  vks: Record<ProofTreeCircuit, RecursiveVk>
}
