// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

export const USER_DATA_ENCRYPTION_CHILD_ARTIFACTS = [
  'ct0_chunk_main',
  'ct0_chunk_main_root',
  'ct0_pk_ct_commit',
  'ct0_chunk_gamma',
  'ct0_eval_chunk_main',
  'ct0_eval_chunk_main_root',
  'ct0_eval_pk_ct',
  'ct0_eval_chunk_identity',
  'ct1_chunk_main',
  'ct1_chunk_main_root',
  'ct1_pk_ct_commit',
  'ct1_chunk_gamma',
  'ct1_eval_chunk_main',
  'ct1_eval_chunk_main_root',
  'ct1_eval_pk_ct',
  'ct1_eval_chunk_identity',
]

export const PRESET_ARTIFACTS = [
  'crisp',
  'crisp_onchain',
  ...USER_DATA_ENCRYPTION_CHILD_ARTIFACTS,
  'user_data_encryption_ct0',
  'user_data_encryption_ct1',
]
