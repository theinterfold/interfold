// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// The secure-16384 preset-bound proof tree, published as a separate entry point.

import type { CircuitBundle, CircuitPreset } from '../circuits'
import type { CompiledCircuit } from '@noir-lang/noir_js'

import crisp from '../../../../circuits/dist/secure-16384/crisp.json'
import crispOnchain from '../../../../circuits/dist/secure-16384/crisp_onchain.json'
import ct0ChunkMain from '../../../../circuits/dist/secure-16384/ct0_chunk_main.json'
import ct0ChunkMainRoot from '../../../../circuits/dist/secure-16384/ct0_chunk_main_root.json'
import ct0PkCtCommit from '../../../../circuits/dist/secure-16384/ct0_pk_ct_commit.json'
import ct0ChunkGamma from '../../../../circuits/dist/secure-16384/ct0_chunk_gamma.json'
import ct0EvalChunkMain from '../../../../circuits/dist/secure-16384/ct0_eval_chunk_main.json'
import ct0EvalChunkMainRoot from '../../../../circuits/dist/secure-16384/ct0_eval_chunk_main_root.json'
import ct0EvalPkCt from '../../../../circuits/dist/secure-16384/ct0_eval_pk_ct.json'
import ct0EvalChunkIdentity from '../../../../circuits/dist/secure-16384/ct0_eval_chunk_identity.json'
import userDataEncryptionCt0 from '../../../../circuits/dist/secure-16384/user_data_encryption_ct0.json'
import ct1ChunkMain from '../../../../circuits/dist/secure-16384/ct1_chunk_main.json'
import ct1ChunkMainRoot from '../../../../circuits/dist/secure-16384/ct1_chunk_main_root.json'
import ct1PkCtCommit from '../../../../circuits/dist/secure-16384/ct1_pk_ct_commit.json'
import ct1ChunkGamma from '../../../../circuits/dist/secure-16384/ct1_chunk_gamma.json'
import ct1EvalChunkMain from '../../../../circuits/dist/secure-16384/ct1_eval_chunk_main.json'
import ct1EvalChunkMainRoot from '../../../../circuits/dist/secure-16384/ct1_eval_chunk_main_root.json'
import ct1EvalPkCt from '../../../../circuits/dist/secure-16384/ct1_eval_pk_ct.json'
import ct1EvalChunkIdentity from '../../../../circuits/dist/secure-16384/ct1_eval_chunk_identity.json'
import userDataEncryptionCt1 from '../../../../circuits/dist/secure-16384/user_data_encryption_ct1.json'

export const preset: CircuitPreset = 'secure-16384'

/** The secure-16384 circuits, ready for `setCircuits()`. */
export const loadCircuits = async (): Promise<CircuitBundle> => ({
  preset,
  crisp: crisp as CompiledCircuit,
  crispOnchain: crispOnchain as CompiledCircuit,
  ct0ChunkMain: ct0ChunkMain as CompiledCircuit,
  ct0ChunkMainRoot: ct0ChunkMainRoot as CompiledCircuit,
  ct0PkCtCommit: ct0PkCtCommit as CompiledCircuit,
  ct0ChunkGamma: ct0ChunkGamma as CompiledCircuit,
  ct0EvalChunkMain: ct0EvalChunkMain as CompiledCircuit,
  ct0EvalChunkMainRoot: ct0EvalChunkMainRoot as CompiledCircuit,
  ct0EvalPkCt: ct0EvalPkCt as CompiledCircuit,
  ct0EvalChunkIdentity: ct0EvalChunkIdentity as CompiledCircuit,
  userDataEncryptionCt0: userDataEncryptionCt0 as CompiledCircuit,
  ct1ChunkMain: ct1ChunkMain as CompiledCircuit,
  ct1ChunkMainRoot: ct1ChunkMainRoot as CompiledCircuit,
  ct1PkCtCommit: ct1PkCtCommit as CompiledCircuit,
  ct1ChunkGamma: ct1ChunkGamma as CompiledCircuit,
  ct1EvalChunkMain: ct1EvalChunkMain as CompiledCircuit,
  ct1EvalChunkMainRoot: ct1EvalChunkMainRoot as CompiledCircuit,
  ct1EvalPkCt: ct1EvalPkCt as CompiledCircuit,
  ct1EvalChunkIdentity: ct1EvalChunkIdentity as CompiledCircuit,
  userDataEncryptionCt1: userDataEncryptionCt1 as CompiledCircuit,
})
