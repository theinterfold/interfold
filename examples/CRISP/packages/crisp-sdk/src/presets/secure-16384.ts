// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// The secure-16384 preset-bound proof tree, published as a separate entry point.

import type { CircuitBundle, CircuitPreset, RecursiveVk } from '../circuits'
import type { CompiledCircuit } from '@noir-lang/noir_js'

import crisp from '../../../../circuits/dist/secure-16384/crisp.json'
import crispOnchain from '../../../../circuits/dist/secure-16384/crisp_onchain.json'
import ct0ChunkMain from '../../../../circuits/dist/secure-16384/ct0_chunk_main.json'
import ct0PkCtCommit from '../../../../circuits/dist/secure-16384/ct0_pk_ct_commit.json'
import ct0EvalChunkIdentity from '../../../../circuits/dist/secure-16384/ct0_eval_chunk_identity.json'
import userDataEncryptionCt0 from '../../../../circuits/dist/secure-16384/user_data_encryption_ct0_chunked.json'
import ct1ChunkMain from '../../../../circuits/dist/secure-16384/ct1_chunk_main.json'
import ct1PkCtCommit from '../../../../circuits/dist/secure-16384/ct1_pk_ct_commit.json'
import ct1EvalChunkIdentity from '../../../../circuits/dist/secure-16384/ct1_eval_chunk_identity.json'
import userDataEncryptionCt1 from '../../../../circuits/dist/secure-16384/user_data_encryption_ct1_chunked.json'
import crispVk from '../../../../circuits/dist/secure-16384/crisp.vk.json'
import crispOnchainVk from '../../../../circuits/dist/secure-16384/crisp_onchain.vk.json'
import ct0ChunkMainVk from '../../../../circuits/dist/secure-16384/ct0_chunk_main.vk.json'
import ct0PkCtCommitVk from '../../../../circuits/dist/secure-16384/ct0_pk_ct_commit.vk.json'
import ct0EvalChunkIdentityVk from '../../../../circuits/dist/secure-16384/ct0_eval_chunk_identity.vk.json'
import userDataEncryptionCt0Vk from '../../../../circuits/dist/secure-16384/user_data_encryption_ct0_chunked.vk.json'
import ct1ChunkMainVk from '../../../../circuits/dist/secure-16384/ct1_chunk_main.vk.json'
import ct1PkCtCommitVk from '../../../../circuits/dist/secure-16384/ct1_pk_ct_commit.vk.json'
import ct1EvalChunkIdentityVk from '../../../../circuits/dist/secure-16384/ct1_eval_chunk_identity.vk.json'
import userDataEncryptionCt1Vk from '../../../../circuits/dist/secure-16384/user_data_encryption_ct1_chunked.vk.json'

export const preset: CircuitPreset = 'secure-16384'

/** The secure-16384 circuits, ready for `setCircuits()`. */
export const loadCircuits = async (): Promise<CircuitBundle> => ({
  preset,
  crisp: crisp as CompiledCircuit,
  crispOnchain: crispOnchain as CompiledCircuit,
  ct0ChunkMain: ct0ChunkMain as CompiledCircuit,
  ct0PkCtCommit: ct0PkCtCommit as CompiledCircuit,
  ct0EvalChunkIdentity: ct0EvalChunkIdentity as CompiledCircuit,
  userDataEncryptionCt0: userDataEncryptionCt0 as CompiledCircuit,
  ct1ChunkMain: ct1ChunkMain as CompiledCircuit,
  ct1PkCtCommit: ct1PkCtCommit as CompiledCircuit,
  ct1EvalChunkIdentity: ct1EvalChunkIdentity as CompiledCircuit,
  userDataEncryptionCt1: userDataEncryptionCt1 as CompiledCircuit,
  vks: {
    crisp: crispVk as RecursiveVk,
    crispOnchain: crispOnchainVk as RecursiveVk,
    ct0ChunkMain: ct0ChunkMainVk as RecursiveVk,
    ct0PkCtCommit: ct0PkCtCommitVk as RecursiveVk,
    ct0EvalChunkIdentity: ct0EvalChunkIdentityVk as RecursiveVk,
    userDataEncryptionCt0: userDataEncryptionCt0Vk as RecursiveVk,
    ct1ChunkMain: ct1ChunkMainVk as RecursiveVk,
    ct1PkCtCommit: ct1PkCtCommitVk as RecursiveVk,
    ct1EvalChunkIdentity: ct1EvalChunkIdentityVk as RecursiveVk,
    userDataEncryptionCt1: userDataEncryptionCt1Vk as RecursiveVk,
  },
})
