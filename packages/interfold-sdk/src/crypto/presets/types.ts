// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { CompiledCircuit } from '@noir-lang/noir_js'

export type UserDataEncryptionProofBundle = {
  ct0ChunkMain: CompiledCircuit
  ct0ChunkMainRoot: CompiledCircuit
  ct0PkCtCommit: CompiledCircuit
  ct0ChunkGamma: CompiledCircuit
  ct0EvalChunkMain: CompiledCircuit
  ct0EvalChunkMainRoot: CompiledCircuit
  ct0EvalPkCt: CompiledCircuit
  ct0EvalChunkIdentity: CompiledCircuit
  userDataEncryptionCt0: CompiledCircuit
  ct1ChunkMain: CompiledCircuit
  ct1ChunkMainRoot: CompiledCircuit
  ct1PkCtCommit: CompiledCircuit
  ct1ChunkGamma: CompiledCircuit
  ct1EvalChunkMain: CompiledCircuit
  ct1EvalChunkMainRoot: CompiledCircuit
  ct1EvalPkCt: CompiledCircuit
  ct1EvalChunkIdentity: CompiledCircuit
  userDataEncryptionCt1: CompiledCircuit
  userDataEncryption: CompiledCircuit
}
