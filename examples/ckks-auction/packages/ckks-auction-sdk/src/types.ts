// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { Address, Hex } from 'viem'

/** On-chain ParamSet the auction runs on (the 12-iteration sign-extraction ladder). */
export const AUCTION_PARAM_SET = 2

/**
 * Normalisation cap pinned by `CkksAuctionE3Program.bidCap`. The auction encrypts RAW bids
 * (cap 1); the *bid bound* (1000) is the ParamSet 2 Greco input bound and the sign-extraction
 * normalisation bound, not this cap.
 */
export const NORMALIZATION_CAP = 1

/** Maximum bid the ParamSet 2 encryption proof admits (`input_bound`) and the sign-map bound. */
export const BID_BOUND = 1000

/** `AUCTION_MERKLE_MAX_DEPTH` compiled into `ckks_auction_validity_ps2`. */
export const MERKLE_MAX_DEPTH = 20

/** Nargo package names of the three legs. */
export const CIRCUIT_NAMES = {
  ct0: 'user_data_encryption_ckks_ct0_ps2',
  ct1: 'user_data_encryption_ckks_ct1_ps2',
  app: 'ckks_auction_validity_ps2',
} as const

export type LegName = keyof typeof CIRCUIT_NAMES

/** One entry of a round's balance snapshot (CRISP token-holder shape). */
export interface BalanceEntry {
  address: Address
  /** Raw integer balance (decimal string). */
  balance: string
}

/** The opening the server serves for one snapshot address (`GET /rounds/{id}/balance-proof/{address}`). */
export interface BalanceProof {
  address: Address
  balance: string
  /** 32-byte hex root the leaf opens to. */
  merkleRoot: Hex
  depth: number
  /** Path direction bits, leaf to root (`false` = node is the left child). */
  indices: boolean[]
  /** Sibling hashes, leaf to root, as decimal field-element strings. */
  siblings: string[]
}

/** A proven leg ready for the envelope. */
export interface ProvenLeg {
  proof: Hex
  /** Exactly the circuit's public inputs/outputs, 32-byte words. */
  publicInputs: Hex[]
}

/** Everything a bidder produces locally; nothing here is secret except that it was derived from the bid. */
export interface BidSubmission {
  ciphertext: Hex
  ct0: ProvenLeg
  ct1: ProvenLeg
  app: ProvenLeg
  mCommitment: Hex
  uCommitment: Hex
  timings: ProvingTimings
}

export interface ProvingTimings {
  encryptMs: number
  executeMs: Record<LegName, number>
  proveMs: Record<LegName, number>
  backendInitMs: number
  totalMs: number
}

export type ProvingStage =
  | { stage: 'encrypt' }
  | { stage: 'backend' }
  | { stage: 'execute'; leg: LegName }
  | { stage: 'prove'; leg: LegName }
  | { stage: 'done' }

export type ProgressCallback = (stage: ProvingStage, elapsedMs: number) => void

/** Round summary as served by the coordination server. */
export interface RoundSummary {
  e3Id: string
  status: RoundStatus
  bidCap: number
  inputWindow: [number, number]
  bidCount: number
  createdAt: number
}

export type RoundStatus = 'requested' | 'active' | 'evaluating' | 'published' | 'finished' | 'failed'

export interface IndexedBid {
  index: number
  publisher: Address
  transactionHash: Hex
  block: number
  ciphertextHash: Hex
  mCommitment: Hex
  uCommitment: Hex
  /** Whether the server fetched and hash-checked the ciphertext from the transaction calldata. */
  ciphertextAvailable: boolean
}

export interface RoundResults {
  /** All `i<j` pairs, in slot order. */
  pairs: [number, number][]
  /** Decoded slot values (canonical fixed point, 2 decimals). */
  values: number[]
  /** `sign(values[p])` per pair: +1 means bidder i outbid bidder j. */
  signs: number[]
  /** Whether every opened slot was a saturated ±1 (|v| within 0.05 of 1). */
  binarized: boolean
  wins: number[]
  winner: number
  /** The winner's on-chain publisher address. */
  winnerAddress: Address | null
}

export interface RoundDetail extends RoundSummary {
  programAddress: Address
  balanceRoot: Hex | null
  snapshot: BalanceEntry[]
  bids: IndexedBid[]
  publicKeyAvailable: boolean
  ceremonyKeys: number
  ceremonyKeysExpected: number
  results: RoundResults | null
  error: string | null
  timings: Record<string, number>
}
