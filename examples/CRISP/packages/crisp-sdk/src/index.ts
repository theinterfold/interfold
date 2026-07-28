// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

export * from './token'
export * from './state'
export * from './api'
export { MAX_MSG_NON_ZERO_COEFFS, MAX_VOTE_OPTIONS, MERKLE_TREE_MAX_DEPTH, SIGNATURE_MESSAGE, SIGNATURE_MESSAGE_HASH } from './constants'
export {
  hashLeaf,
  generateMerkleProof,
  generateMerkleTree,
  getAddressFromSignature,
  getMaxVoteValue,
  getZeroVote,
  getScaledBalance,
} from './utils'
export {
  decodeTally,
  generateVoteProof,
  generateMaskVoteProof,
  verifyProof,
  generateBFVKeys,
  encryptVote,
  encodeSolidityProof,
  validateVote,
  destroyBBApi,
} from './vote'
export { CrispSDK } from './sdk'

export type {
  OnChainRoundData,
  RoundDetails,
  TokenDetails,
  Vote,
  MaskVoteProofInputs,
  VoteProofInputs,
  ProofData,
  CurrentRoundResponse,
  E3StateLiteResponse,
  JsonResponse,
  NewRoundRequest,
  BroadcastVoteRequest,
  BroadcastVoteResponse,
  VoteResponseStatus,
  VoteStatusResponse,
  WebResultResponse,
  TokenHolder,
} from './types'
export { CreditMode } from './types'
