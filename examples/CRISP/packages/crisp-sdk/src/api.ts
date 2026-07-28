// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import {
  CRISP_SERVER_ELIGIBLE_ADDRESSES_ENDPOINT,
  CRISP_SERVER_ROUNDS_CIPHERTEXT_ENDPOINT,
  CRISP_SERVER_ROUNDS_CURRENT_ENDPOINT,
  CRISP_SERVER_ROUNDS_PUBLIC_KEY_ENDPOINT,
  CRISP_SERVER_ROUNDS_REQUEST_ENDPOINT,
  CRISP_SERVER_STATE_ALL_ENDPOINT,
  CRISP_SERVER_STATE_LITE_ENDPOINT,
  CRISP_SERVER_STATE_RESULT_ENDPOINT,
  CRISP_SERVER_TOKEN_TREE_ENDPOINT,
  CRISP_SERVER_VOTING_BROADCAST_ENDPOINT,
  CRISP_SERVER_VOTING_STATUS_ENDPOINT,
} from './constants'

import type {
  BroadcastVoteRequest,
  BroadcastVoteResponse,
  CurrentRoundResponse,
  E3StateLiteResponse,
  JsonResponse,
  NewRoundRequest,
  TokenHolder,
  VoteStatusResponse,
  WebResultResponse,
} from './types'

/**
 * POST a JSON body to a CRISP server endpoint and parse the JSON response.
 * @param serverUrl - The base URL of the CRISP server
 * @param endpoint - The endpoint path (without leading slash)
 * @param body - The request body to serialize as JSON
 * @returns The parsed JSON response
 * @throws If the server responds with a non-OK status
 */
const postJson = async <TResponse>(serverUrl: string, endpoint: string, body: unknown): Promise<TResponse> => {
  const response = await fetch(`${serverUrl}/${endpoint}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  })

  if (!response.ok) {
    throw new Error(`CRISP server request to /${endpoint} failed (${response.status}): ${await response.text()}`)
  }

  return (await response.json()) as TResponse
}

/**
 * Get the current (most recent) round, optionally filtered by requester addresses.
 * Returns undefined when no current round exists (404).
 * @param serverUrl - The base URL of the CRISP server
 * @param requesters - Optional list of requester addresses to filter by (only the first is used by the server)
 * @returns The current round id, or undefined if none exists
 */
export const getCurrentRound = async (serverUrl: string, requesters: string[] = []): Promise<CurrentRoundResponse | undefined> => {
  const response = await fetch(`${serverUrl}/${CRISP_SERVER_ROUNDS_CURRENT_ENDPOINT}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ requesters }),
  })

  if (response.status === 404) {
    return undefined
  }

  if (!response.ok) {
    throw new Error(`Failed to fetch current round (${response.status}): ${await response.text()}`)
  }

  return (await response.json()) as CurrentRoundResponse
}

/**
 * Get the committee public key for a given round.
 * @param serverUrl - The base URL of the CRISP server
 * @param e3Id - The e3Id of the round
 * @returns The committee public key bytes
 */
export const getRoundPublicKey = async (serverUrl: string, e3Id: number): Promise<Uint8Array> => {
  const data = await postJson<{ round_id: number; pk_bytes: number[] }>(serverUrl, CRISP_SERVER_ROUNDS_PUBLIC_KEY_ENDPOINT, {
    round_id: e3Id,
    pk_bytes: [],
  })

  return new Uint8Array(data.pk_bytes)
}

/**
 * Get the ciphertext output for a given round.
 * @param serverUrl - The base URL of the CRISP server
 * @param e3Id - The e3Id of the round
 * @returns The ciphertext output bytes
 */
export const getRoundCiphertext = async (serverUrl: string, e3Id: number): Promise<Uint8Array> => {
  const data = await postJson<{ round_id: number; ct_bytes: number[] }>(serverUrl, CRISP_SERVER_ROUNDS_CIPHERTEXT_ENDPOINT, {
    round_id: e3Id,
    ct_bytes: [],
  })

  return new Uint8Array(data.ct_bytes)
}

/**
 * Request a new E3 round. Requires the server's cron API key.
 * @param serverUrl - The base URL of the CRISP server
 * @param request - The new round request (cron API key, token address and balance threshold)
 * @returns The server confirmation message
 */
export const requestNewRound = async (serverUrl: string, request: NewRoundRequest): Promise<JsonResponse> =>
  postJson<JsonResponse>(serverUrl, CRISP_SERVER_ROUNDS_REQUEST_ENDPOINT, {
    cron_api_key: request.cronApiKey,
    token_address: request.tokenAddress,
    balance_threshold: request.balanceThreshold,
  })

/**
 * Broadcast an encrypted vote through the CRISP server, which relays it on-chain.
 * @param serverUrl - The base URL of the CRISP server
 * @param request - The vote request (round id, hex encoded proof and voter address)
 * @returns The broadcast result, including the transaction hash on success
 */
export const broadcastVote = async (serverUrl: string, request: BroadcastVoteRequest): Promise<BroadcastVoteResponse> => {
  const response = await fetch(`${serverUrl}/${CRISP_SERVER_VOTING_BROADCAST_ENDPOINT}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      round_id: request.e3Id,
      encoded_proof: request.encodedProof,
      address: request.address,
    }),
  })

  // The server returns a structured VoteResponse body for broadcast failures (500) as well
  const data = (await response.json()) as BroadcastVoteResponse | string

  if (typeof data === 'string') {
    throw new Error(`Failed to broadcast vote (${response.status}): ${data}`)
  }

  return data
}

/**
 * Get the vote status for an address in a specific round.
 * @param serverUrl - The base URL of the CRISP server
 * @param e3Id - The e3Id of the round
 * @param address - The voter address
 * @returns The vote status for the address
 */
export const getVoteStatus = async (serverUrl: string, e3Id: number, address: string): Promise<VoteStatusResponse> =>
  postJson<VoteStatusResponse>(serverUrl, CRISP_SERVER_VOTING_STATUS_ENDPOINT, { round_id: e3Id, address })

/**
 * Get the result for a given round.
 * @param serverUrl - The base URL of the CRISP server
 * @param e3Id - The e3Id of the round
 * @returns The round result (tally, emojis, total votes, end time and requester)
 */
export const getRoundResult = async (serverUrl: string, e3Id: number): Promise<WebResultResponse> =>
  postJson<WebResultResponse>(serverUrl, CRISP_SERVER_STATE_RESULT_ENDPOINT, { round_id: e3Id })

/**
 * Get the results for all rounds, optionally filtered by requester addresses.
 * @param serverUrl - The base URL of the CRISP server
 * @param requesters - Optional list of requester addresses to filter by
 * @returns The results for all matching rounds
 */
export const getAllRoundResults = async (serverUrl: string, requesters: string[] = []): Promise<WebResultResponse[]> =>
  postJson<WebResultResponse[]>(serverUrl, CRISP_SERVER_STATE_ALL_ENDPOINT, { requesters })

/**
 * Get the lite state for a given round, as returned by the server (snake_case fields).
 * See `getRoundDetails` in `state.ts` for a camelCase convenience wrapper over this endpoint.
 * @param serverUrl - The base URL of the CRISP server
 * @param e3Id - The e3Id of the round
 * @returns The lite round state
 */
export const getRoundStateLite = async (serverUrl: string, e3Id: number): Promise<E3StateLiteResponse> =>
  postJson<E3StateLiteResponse>(serverUrl, CRISP_SERVER_STATE_LITE_ENDPOINT, { round_id: e3Id })

/**
 * Get the token holder hashes (hash(address, balance)) for a given round.
 * These are the Merkle tree leaves used for eligibility proofs.
 * @param serverUrl - The base URL of the CRISP server
 * @param e3Id - The e3Id of the round
 * @returns The list of token holder hashes
 */
export const getTokenHolderHashes = async (serverUrl: string, e3Id: number): Promise<string[]> =>
  postJson<string[]>(serverUrl, CRISP_SERVER_TOKEN_TREE_ENDPOINT, { round_id: e3Id })

/**
 * Get the eligible addresses and their balances for a given round.
 * @param serverUrl - The base URL of the CRISP server
 * @param e3Id - The e3Id of the round
 * @returns The list of eligible token holders
 */
export const getEligibleAddresses = async (serverUrl: string, e3Id: number): Promise<TokenHolder[]> =>
  postJson<TokenHolder[]>(serverUrl, CRISP_SERVER_ELIGIBLE_ADDRESSES_ENDPOINT, { round_id: e3Id })
