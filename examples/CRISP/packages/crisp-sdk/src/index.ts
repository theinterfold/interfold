// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

export { setCircuits, getRegisteredCircuits, registeredPreset, requireCircuits, type CircuitBundle, type CircuitPreset } from './circuits'
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
  encodeVote,
  decodeTally,
  decryptVote,
  prepareBallot,
  prepareCircuitInputs,
  finishBallotProof,
  finishMaskProof,
  splitDigest,
  verifyProof,
  generateBFVKeys,
  encryptVote,
  encodeSolidityProof,
  validateVote,
  destroyBBApi,
} from './vote'
export { CrispSDK, SERVER_RPC } from './sdk'
export type { VerifyAgainstChain } from './sdk'
export { resolveSlotHead, resolveSlotHeadOnChain, getOnChainInputRecords } from './slotHead'
export type { SlotHeadResolution } from './slotHead'

export type {
  ChainHead,
  ContractRead,
  ContractReadResult,
  IndexedLog,
  LogQuery,
  OnChainRoundData,
  RoundDetails,
  TokenDetails,
  Vote,
  CensusVariant,
  PrepareBallotInputs,
  PrepareBallotRequest,
  PreparedBallot,
  ProofData,
  SlotHead,
  SlotEntry,
  OnChainInputRecord,
  ResolvedSlotHead,
  SlotEntryRejection,
  TallyResult,
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
