// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

export {
  getThresholdBfvParamsSet,
  generatePublicKey,
  computeCiphertextCommitment,
  computePublicKeyCommitment,
  openLbfvKeyEnvelope,
  encryptNumber,
  encryptVector,
  encryptNumberAndGenInputs,
  encryptNumberAndGenProof,
  encryptVectorAndGenInputs,
  encryptVectorAndGenProof,
} from './encrypt'
export type { VectorEncoding, VectorEncryptOptions } from './encrypt'

export { generateProof } from './user-data-encryption'

export type {
  BfvParams,
  LbfvKeyEnvelopeOpening,
  ThresholdBfvParamsPresetName,
  VerifiableEncryptionResult,
  EncryptedValueAndPublicInputs,
} from './types'

export { ThresholdBfvParamsPresetNames } from './types'
