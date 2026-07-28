// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import {
  broadcastVote,
  getAllRoundResults,
  getCurrentRound,
  getEligibleAddresses,
  getRoundCiphertext,
  getRoundPublicKey,
  getRoundResult,
  getRoundStateLite,
  getTokenHolderHashes,
  getVoteStatus,
  requestNewRound,
} from './api'
import { getOnChainRoundData, getPreviousCiphertext, getRoundDetails, getRoundTokenDetails } from './state'
import { generateMaskVoteProof, generateVoteProof } from './vote'

import type {
  BroadcastVoteRequest,
  BroadcastVoteResponse,
  CurrentRoundResponse,
  E3StateLiteResponse,
  JsonResponse,
  MaskVoteProofRequest,
  NewRoundRequest,
  OnChainRoundData,
  ProofData,
  RoundDetails,
  TokenDetails,
  TokenHolder,
  VoteProofRequest,
  VoteStatusResponse,
  WebResultResponse,
} from './types'

/**
 * A class representing the CRISP SDK.
 */
export class CrispSDK {
  /**
   * The server URL for the CRISP SDK.
   * It's used by methods that communicate directly with the CRISP server.
   */
  private serverUrl: string

  /**
   * Create a new instance.
   * @param serverUrl
   */
  constructor(serverUrl: string) {
    this.serverUrl = serverUrl
  }

  /**
   * Generate a proof for a vote masking.
   * @param maskProofInputs - The inputs required to generate the mask vote proof.
   * @returns A promise that resolves to the generated proof data.
   */
  async generateMaskVoteProof(maskProofInputs: MaskVoteProofRequest): Promise<ProofData> {
    const previousCiphertext = await getPreviousCiphertext(this.serverUrl, maskProofInputs.e3Id, maskProofInputs.slotAddress)

    return generateMaskVoteProof({
      ...maskProofInputs,
      previousCiphertext,
    })
  }

  /**
   * Generate a proof for a vote.
   *
   * Note: The previous ciphertext is not used in the proof computation. This method still calls
   * the same server API (previous-ciphertext) as {@link generateMaskVoteProof} to prevent the
   * server from inferring the vote type (mask vs normal) from the client's API usage pattern.
   *
   * @param voteProofInputs - The inputs required to generate the vote proof.
   * @returns A promise that resolves to the generated proof data.
   */
  async generateVoteProof(voteProofInputs: VoteProofRequest): Promise<ProofData> {
    const previousCiphertext = await getPreviousCiphertext(this.serverUrl, voteProofInputs.e3Id, voteProofInputs.slotAddress)

    return generateVoteProof({
      ...voteProofInputs,
      previousCiphertext,
    })
  }

  /**
   * Get the current (most recent) round, optionally filtered by requester addresses.
   * @param requesters - Optional list of requester addresses to filter by
   * @returns The current round id, or undefined if no round exists
   */
  async getCurrentRound(requesters?: string[]): Promise<CurrentRoundResponse | undefined> {
    return getCurrentRound(this.serverUrl, requesters)
  }

  /**
   * Get the committee public key for a given round.
   * @param e3Id - The e3Id of the round
   * @returns The committee public key bytes
   */
  async getRoundPublicKey(e3Id: number): Promise<Uint8Array> {
    return getRoundPublicKey(this.serverUrl, e3Id)
  }

  /**
   * Get the ciphertext output for a given round.
   * @param e3Id - The e3Id of the round
   * @returns The ciphertext output bytes
   */
  async getRoundCiphertext(e3Id: number): Promise<Uint8Array> {
    return getRoundCiphertext(this.serverUrl, e3Id)
  }

  /**
   * Request a new E3 round. Requires the server's cron API key.
   * @param request - The new round request (cron API key, token address and balance threshold)
   * @returns The server confirmation message
   */
  async requestNewRound(request: NewRoundRequest): Promise<JsonResponse> {
    return requestNewRound(this.serverUrl, request)
  }

  /**
   * Broadcast an encrypted vote through the CRISP server, which relays it on-chain.
   * @param request - The vote request (round id, hex encoded proof and voter address)
   * @returns The broadcast result, including the transaction hash on success
   */
  async broadcastVote(request: BroadcastVoteRequest): Promise<BroadcastVoteResponse> {
    return broadcastVote(this.serverUrl, request)
  }

  /**
   * Get the vote status for an address in a specific round.
   * @param e3Id - The e3Id of the round
   * @param address - The voter address
   * @returns The vote status for the address
   */
  async getVoteStatus(e3Id: number, address: string): Promise<VoteStatusResponse> {
    return getVoteStatus(this.serverUrl, e3Id, address)
  }

  /**
   * Get the result for a given round.
   * @param e3Id - The e3Id of the round
   * @returns The round result (tally, emojis, total votes, end time and requester)
   */
  async getRoundResult(e3Id: number): Promise<WebResultResponse> {
    return getRoundResult(this.serverUrl, e3Id)
  }

  /**
   * Get the results for all rounds, optionally filtered by requester addresses.
   * @param requesters - Optional list of requester addresses to filter by
   * @returns The results for all matching rounds
   */
  async getAllRoundResults(requesters?: string[]): Promise<WebResultResponse[]> {
    return getAllRoundResults(this.serverUrl, requesters)
  }

  /**
   * Get the lite state for a given round, as returned by the server (snake_case fields).
   * @param e3Id - The e3Id of the round
   * @returns The lite round state
   */
  async getRoundStateLite(e3Id: number): Promise<E3StateLiteResponse> {
    return getRoundStateLite(this.serverUrl, e3Id)
  }

  /**
   * Get the details of a specific round in a camelCase convenience format.
   * @param e3Id - The e3Id of the round
   * @returns The round details
   */
  async getRoundDetails(e3Id: number): Promise<RoundDetails> {
    return getRoundDetails(this.serverUrl, e3Id)
  }

  /**
   * Get the round data stored in the CRISPProgram contract, read directly from the chain.
   *
   * When the chain id is omitted it is looked up on the CRISP server.
   *
   * @param programAddress - The address of the CRISPProgram contract
   * @param e3Id - The e3Id of the round
   * @param chainId - The chain ID of the network the program is deployed on
   * @returns The on chain round data
   */
  async getOnChainRoundData(programAddress: string, e3Id: number, chainId?: number): Promise<OnChainRoundData> {
    const chain = chainId ?? Number((await getRoundDetails(this.serverUrl, e3Id)).chainId)

    return getOnChainRoundData(programAddress, e3Id, chain)
  }

  /**
   * Get the token address, balance threshold and snapshot block for a specific round.
   * @param e3Id - The e3Id of the round
   * @returns The token details
   */
  async getRoundTokenDetails(e3Id: number): Promise<TokenDetails> {
    return getRoundTokenDetails(this.serverUrl, e3Id)
  }

  /**
   * Get the token holder hashes (hash(address, balance)) for a given round.
   * These are the Merkle tree leaves used for eligibility proofs.
   * @param e3Id - The e3Id of the round
   * @returns The list of token holder hashes
   */
  async getTokenHolderHashes(e3Id: number): Promise<string[]> {
    return getTokenHolderHashes(this.serverUrl, e3Id)
  }

  /**
   * Get the eligible addresses and their balances for a given round.
   * @param e3Id - The e3Id of the round
   * @returns The list of eligible token holders
   */
  async getEligibleAddresses(e3Id: number): Promise<TokenHolder[]> {
    return getEligibleAddresses(this.serverUrl, e3Id)
  }

  /**
   * Get the previous ciphertext input for a slot address in a given round.
   * @param e3Id - The e3Id of the round
   * @param address - The address of the slot
   * @returns The previous ciphertext, or undefined if the slot is empty
   */
  async getPreviousCiphertext(e3Id: number, address: string): Promise<Uint8Array | undefined> {
    return getPreviousCiphertext(this.serverUrl, e3Id, address)
  }
}
