// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { CreditMode } from '@crisp-e3/sdk'

/**
 * Where a round's electorate comes from. Mirrors `CensusMode` in the CRISP server and
 * `CRISPProgram`, including the discriminants — they cross the wire as numbers.
 */
export enum CensusMode {
  Token = 0,
  ByRequester = 1,
  Onchain = 2,
}

export interface VotingRound {
  round_id: string
  pk_bytes: number[]
}

export interface CurrentRound {
  id: string
}

/// Carries no address: the slot is already inside the encoded proof, and every byte the relay
/// does not receive is a byte it cannot log against a masker's session.
export interface BroadcastVoteRequest {
  round_id: string
  encoded_proof: string
}

export type VoteResponseStatus = 'success' | 'pending_commitment' | 'ready_for_commitment' | 'pending_availability' | 'failed_broadcast'
export interface BroadcastVoteResponse {
  status: VoteResponseStatus
  tx_hash: string | null
  job_id: string | null
  encoded_proof: string | null
  message: string | null
}

export interface VoteStatusRequest {
  round_id: string
  address: string
}

/// `slot_active` reports that the slot holds at least one published entry — not that its owner
/// voted. Masks are indistinguishable from votes, so activity is all the server can answer.
export interface VoteStatusResponse {
  round_id: string
  address: string
  slot_active: boolean
  round_status?: string
}

export interface VoteStateLite {
  id: string
  chain_id: number
  interfold_address: string

  status: string
  vote_count: number

  start_time: number
  end_time: number
  start_block: number
  snapshot_block: number

  committee_public_key: number[]
  emojis: [string, string]

  /// The token the round reads eligibility from. For an ONCHAIN round this is what the client
  /// reads registrants and voting power from; unused for the Merkle modes.
  token_address: string

  credit_mode: CreditMode
  census_mode: CensusMode
  credits?: number
}

export type Vote = number[]

export interface EligibleVoter {
  address: string
  balance: number
}
