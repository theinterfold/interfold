// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { LeanIMTMerkleProof } from '@zk-kit/lean-imt'

/**
 * Type representing the details of a specific round returned by the CRISP server
 */
export type RoundDetailsResponse = {
  id: string
  chain_id: string
  interfold_address: string
  status: string
  vote_count: string
  start_time: string
  duration: string
  expiration: string
  start_block: string
  committee_public_key: string[]
  emojis: [string, string]
  token_address: string
  balance_threshold: string
}

/**
 * Type representing the details of a specific round in a more convenient format
 */
export type RoundDetails = {
  e3Id: bigint
  chainId: bigint
  interfoldAddress: string
  status: string
  voteCount: bigint
  startTime: bigint
  duration: bigint
  expiration: bigint
  startBlock: bigint
  committeePublicKey: string[]
  emojis: [string, string]
  tokenAddress: string
  balanceThreshold: bigint
}

/**
 * Type representing the token details required for participation in a round
 */
export type TokenDetails = {
  tokenAddress: string
  threshold: bigint
  snapshotBlock: bigint
}

/**
 * Type representing a Merkle proof
 */
export type MerkleProof = {
  leaf: bigint
  index: number
  proof: LeanIMTMerkleProof<bigint>
  length: number
  indices: number[]
}

/**
 * Type representing a vote
 */
export type Vote = number[]

/**
 * Type representing a vector with coefficients
 */
export type Polynomial = {
  coefficients: string[]
}

/**
 * Type representing cryptographic parameters
 */
export type GrecoCryptographicParams = {
  q_mod_t: string
  qis: string[]
  k0is: string[]
}

/**
 * Type representing Greco bounds
 */
export type GrecoBoundParams = {
  e_bound: string
  u_bound: string
  k1_low_bound: string
  k1_up_bound: string
  p1_bounds: string[]
  p2_bounds: string[]
  pk_bounds: string[]
  r1_low_bounds: string[]
  r1_up_bounds: string[]
  r2_bounds: string[]
}

/**
 * Type representing Greco parameters
 */
export type GrecoParams = {
  crypto: GrecoCryptographicParams
  bounds: GrecoBoundParams
}

export type ProofData = {
  publicInputs: string[]
  proof: Uint8Array
  encryptedVote: Uint8Array
}

export type ProofInputs = {
  previousCiphertext?: Uint8Array
  vote: Vote
  publicKey: Uint8Array
  signature: `0x${string}`
  messageHash: `0x${string}`
  balance: bigint
  slotAddress: string
  merkleProof: MerkleProof
  isMaskVote: boolean
}

export type MaskVoteProofInputs = {
  publicKey: Uint8Array
  balance: bigint
  slotAddress: string
  merkleLeaves: string[] | bigint[]
  previousCiphertext?: Uint8Array
  numOptions: number
}

export type MaskVoteProofRequest = {
  e3Id: number
  publicKey: Uint8Array
  balance: bigint
  slotAddress: string
  merkleLeaves: string[] | bigint[]
  numOptions: number
}

export type VoteProofInputs = {
  merkleLeaves: string[] | bigint[]
  publicKey: Uint8Array
  balance: bigint
  vote: Vote
  signature: `0x${string}`
  messageHash: `0x${string}`
  slotAddress: string
  previousCiphertext?: Uint8Array
}

export type VoteProofRequest = {
  e3Id: number
  merkleLeaves: string[] | bigint[]
  publicKey: Uint8Array
  balance: bigint
  vote: Vote
  signature: `0x${string}`
  messageHash: `0x${string}`
  slotAddress: string
}

/**
 * Enum representing the credit mode for a round, which can be either constant or custom.
 * In constant mode, all voters receive the same amount of credits, while in custom mode,
 * the credits can vary based on certain criteria (e.g., voter balance).
 */
export enum CreditMode {
  CONSTANT = 0,
  CUSTOM = 1,
}
