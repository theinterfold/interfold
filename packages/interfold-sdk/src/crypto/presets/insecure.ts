// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { CompiledCircuit } from '@noir-lang/noir_js'
import type { RecursiveVk, UserDataEncryptionProofBundle } from './types'

import ct0ChunkMain from '../../../circuits/dist/insecure/ct0_chunk_main.json'
import ct0PkCtCommit from '../../../circuits/dist/insecure/ct0_pk_ct_commit.json'
import ct0EvalChunkIdentity from '../../../circuits/dist/insecure/ct0_eval_chunk_identity.json'
import userDataEncryptionCt0 from '../../../circuits/dist/insecure/user_data_encryption_ct0_chunked.json'
import ct1ChunkMain from '../../../circuits/dist/insecure/ct1_chunk_main.json'
import ct1PkCtCommit from '../../../circuits/dist/insecure/ct1_pk_ct_commit.json'
import ct1EvalChunkIdentity from '../../../circuits/dist/insecure/ct1_eval_chunk_identity.json'
import userDataEncryptionCt1 from '../../../circuits/dist/insecure/user_data_encryption_ct1_chunked.json'
import userDataEncryption from '../../../circuits/dist/insecure/user_data_encryption_chunked.json'
import ct0ChunkMainVk from '../../../circuits/dist/insecure/ct0_chunk_main.vk.json'
import ct0PkCtCommitVk from '../../../circuits/dist/insecure/ct0_pk_ct_commit.vk.json'
import ct0EvalChunkIdentityVk from '../../../circuits/dist/insecure/ct0_eval_chunk_identity.vk.json'
import userDataEncryptionCt0Vk from '../../../circuits/dist/insecure/user_data_encryption_ct0_chunked.vk.json'
import ct1ChunkMainVk from '../../../circuits/dist/insecure/ct1_chunk_main.vk.json'
import ct1PkCtCommitVk from '../../../circuits/dist/insecure/ct1_pk_ct_commit.vk.json'
import ct1EvalChunkIdentityVk from '../../../circuits/dist/insecure/ct1_eval_chunk_identity.vk.json'
import userDataEncryptionCt1Vk from '../../../circuits/dist/insecure/user_data_encryption_ct1_chunked.vk.json'

export const insecureProofBundle: UserDataEncryptionProofBundle = {
  ct0ChunkMain: ct0ChunkMain as CompiledCircuit,
  ct0PkCtCommit: ct0PkCtCommit as CompiledCircuit,
  ct0EvalChunkIdentity: ct0EvalChunkIdentity as CompiledCircuit,
  userDataEncryptionCt0: userDataEncryptionCt0 as CompiledCircuit,
  ct1ChunkMain: ct1ChunkMain as CompiledCircuit,
  ct1PkCtCommit: ct1PkCtCommit as CompiledCircuit,
  ct1EvalChunkIdentity: ct1EvalChunkIdentity as CompiledCircuit,
  userDataEncryptionCt1: userDataEncryptionCt1 as CompiledCircuit,
  userDataEncryption: userDataEncryption as CompiledCircuit,
  vks: {
    ct0ChunkMain: ct0ChunkMainVk as RecursiveVk,
    ct0PkCtCommit: ct0PkCtCommitVk as RecursiveVk,
    ct0EvalChunkIdentity: ct0EvalChunkIdentityVk as RecursiveVk,
    userDataEncryptionCt0: userDataEncryptionCt0Vk as RecursiveVk,
    ct1ChunkMain: ct1ChunkMainVk as RecursiveVk,
    ct1PkCtCommit: ct1PkCtCommitVk as RecursiveVk,
    ct1EvalChunkIdentity: ct1EvalChunkIdentityVk as RecursiveVk,
    userDataEncryptionCt1: userDataEncryptionCt1Vk as RecursiveVk,
  },
}
