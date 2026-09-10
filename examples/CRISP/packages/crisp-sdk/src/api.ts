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
  CRISP_SERVER_VOTING_AVAILABILITY_ENDPOINT,
  CRISP_SERVER_VOTING_STATUS_ENDPOINT,
  CRISP_SERVER_CHAIN_HEAD_ENDPOINT,
  CRISP_SERVER_CHAIN_READ_ENDPOINT,
  CRISP_SERVER_CHAIN_LOGS_ENDPOINT,
  CRISP_SERVER_CHAIN_BLOCK_AT_TIMESTAMP_ENDPOINT,
  CRISP_SERVER_CHAIN_RPC_ENDPOINT,
} from './constants'

import type {
  ChainHead,
  ContractRead,
  ContractReadResult,
  IndexedLog,
  LogQuery,
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
export const getRoundPublicKey = async (serverUrl: string, e3Id: bigint): Promise<Uint8Array> => {
  const data = await postJson<{ round_id: string; pk_bytes: number[] }>(serverUrl, CRISP_SERVER_ROUNDS_PUBLIC_KEY_ENDPOINT, {
    round_id: e3Id.toString(),
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
export const getRoundCiphertext = async (serverUrl: string, e3Id: bigint): Promise<Uint8Array> => {
  const data = await postJson<{ round_id: string; ct_bytes: number[] }>(serverUrl, CRISP_SERVER_ROUNDS_CIPHERTEXT_ENDPOINT, {
    round_id: e3Id.toString(),
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
    census_mode: request.censusMode,
  })

/**
 * Stage an encrypted vote with the CRISP availability service.
 *
 * This call returns after the proof commitment is accepted or the server creates a 10-minute
 * commitment payload for the voter's wallet. The server publishes the ciphertext to Avail and
 * finalizes the input in the background after the commitment lands.
 * @param serverUrl - The base URL of the CRISP server
 * @param request - The vote request (round id and hex encoded proof)
 * @returns The broadcast result, including the transaction hash on success
 */
export const broadcastVote = async (serverUrl: string, request: BroadcastVoteRequest): Promise<BroadcastVoteResponse> => {
  const response = await fetch(`${serverUrl}/${CRISP_SERVER_VOTING_BROADCAST_ENDPOINT}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      round_id: request.e3Id.toString(),
      encoded_proof: request.encodedProof,
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
 * Read a durable vote availability job without waiting for VectorX finalization.
 * @param serverUrl The base URL of the CRISP server.
 * @param jobId The job id returned by {@link broadcastVote}.
 * @returns The current commitment or availability state.
 */
export const getVoteAvailability = async (serverUrl: string, jobId: string): Promise<BroadcastVoteResponse> => {
  const response = await fetch(`${serverUrl}/${CRISP_SERVER_VOTING_AVAILABILITY_ENDPOINT}/${encodeURIComponent(jobId)}`)
  if (!response.ok) {
    throw new Error(`Failed to read availability job (${response.status}): ${await response.text()}`)
  }
  return (await response.json()) as BroadcastVoteResponse
}

/**
 * Get the vote status for an address in a specific round.
 * @param serverUrl - The base URL of the CRISP server
 * @param e3Id - The e3Id of the round
 * @param address - The voter address
 * @returns The vote status for the address
 */
export const getVoteStatus = async (serverUrl: string, e3Id: bigint, address: string): Promise<VoteStatusResponse> =>
  postJson<VoteStatusResponse>(serverUrl, CRISP_SERVER_VOTING_STATUS_ENDPOINT, { round_id: e3Id.toString(), address })

/**
 * Get the result for a given round.
 * @param serverUrl - The base URL of the CRISP server
 * @param e3Id - The e3Id of the round
 * @returns The round result (tally, emojis, total votes, end time and requester)
 */
export const getRoundResult = async (serverUrl: string, e3Id: bigint): Promise<WebResultResponse> =>
  postJson<WebResultResponse>(serverUrl, CRISP_SERVER_STATE_RESULT_ENDPOINT, { round_id: e3Id.toString() })

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
export const getRoundStateLite = async (serverUrl: string, e3Id: bigint): Promise<E3StateLiteResponse> =>
  postJson<E3StateLiteResponse>(serverUrl, CRISP_SERVER_STATE_LITE_ENDPOINT, { round_id: e3Id.toString() })

/**
 * Get the token holder hashes (hash(address, balance)) for a given round.
 * These are the Merkle tree leaves used for eligibility proofs.
 * @param serverUrl - The base URL of the CRISP server
 * @param e3Id - The e3Id of the round
 * @returns The list of token holder hashes
 */
export const getTokenHolderHashes = async (serverUrl: string, e3Id: bigint): Promise<string[]> =>
  postJson<string[]>(serverUrl, CRISP_SERVER_TOKEN_TREE_ENDPOINT, { round_id: e3Id.toString() })

/**
 * Get the eligible addresses and their balances for a given round.
 * @param serverUrl - The base URL of the CRISP server
 * @param e3Id - The e3Id of the round
 * @returns The list of eligible token holders
 */
export const getEligibleAddresses = async (serverUrl: string, e3Id: bigint): Promise<TokenHolder[]> =>
  postJson<TokenHolder[]>(serverUrl, CRISP_SERVER_ELIGIBLE_ADDRESSES_ENDPOINT, { round_id: e3Id.toString() })

/**
 * The chain head (block number, timestamp, chain id) as seen by the CRISP server.
 *
 * One call in place of polling `eth_blockNumber` from every hook that wants to know whether
 * something has advanced, and it carries the timestamp so a caller deciding whether a voting
 * window has closed does not need a second round trip for the block.
 *
 * @param serverUrl - The base URL of the CRISP server
 * @returns The current head
 */
export const getChainHead = async (serverUrl: string): Promise<ChainHead> => {
  const data = await postJson<{ block_number: number | string; timestamp: number | string; chain_id: number }>(
    serverUrl,
    CRISP_SERVER_CHAIN_HEAD_ENDPOINT,
    {},
  )

  return {
    blockNumber: BigInt(data.block_number),
    timestamp: BigInt(data.timestamp),
    chainId: Number(data.chain_id),
  }
}

/**
 * Read allowlisted contracts through the CRISP server, batched.
 *
 * Point reads are answered from the chain rather than from the server's index on purpose: they
 * are per-account and change constantly, and a stale answer here is not a slow UI but a wrong
 * balance or a voter wrongly told they cannot vote.
 *
 * @param serverUrl - The base URL of the CRISP server
 * @param calls - The calls to perform, in order
 * @returns One result per call, in the same order
 */
export const readContracts = async (serverUrl: string, calls: ContractRead[]): Promise<ContractReadResult[]> => {
  if (calls.length === 0) return []

  const data = await postJson<{ result: string | null; error: string | null }[]>(serverUrl, CRISP_SERVER_CHAIN_READ_ENDPOINT, {
    calls: calls.map((call) => ({
      address: call.address,
      data: call.data,
      block_number: call.blockNumber !== undefined ? Number(call.blockNumber) : undefined,
    })),
  })

  return data.map((entry) => ({
    result: entry.result ? (entry.result as `0x${string}`) : undefined,
    error: entry.error ?? undefined,
  }))
}

/**
 * Query logs for an allowlisted contract over an arbitrary block range.
 *
 * The range needs no chunking by the caller: the server splits it into windows the upstream
 * provider accepts, which is the whole reason clients otherwise carry range-splitting code.
 *
 * It is still BOUNDED — the server refuses a span wider than a million blocks, and `fromBlock`
 * defaults to 0, so a query naming only an address is rejected on a long-lived chain. Pass the
 * contract's deployment block as `fromBlock`; that is the intended usage and always in range.
 *
 * @param serverUrl - The base URL of the CRISP server
 * @param query - The log query
 * @returns The matching logs, ordered by block and log index
 */
export const getIndexedLogs = async (serverUrl: string, query: LogQuery): Promise<IndexedLog[]> => {
  const data = await postJson<
    {
      address: string
      topics: string[]
      data: string
      block_number: number | null
      transaction_hash: string | null
      log_index: number | null
    }[]
  >(serverUrl, CRISP_SERVER_CHAIN_LOGS_ENDPOINT, {
    address: query.address,
    topics: (query.topics ?? []).map((topic) => topic ?? null),
    from_block: query.fromBlock !== undefined ? Number(query.fromBlock) : undefined,
    to_block: query.toBlock !== undefined ? Number(query.toBlock) : undefined,
  })

  return data.map((log) => ({
    address: log.address,
    topics: log.topics as `0x${string}`[],
    data: log.data as `0x${string}`,
    blockNumber: log.block_number !== null ? BigInt(log.block_number) : undefined,
    transactionHash: log.transaction_hash ?? undefined,
    logIndex: log.log_index ?? undefined,
  }))
}

/**
 * The last block at or before a timestamp.
 *
 * Clients need this to turn a proposal's snapshot timepoint into a block. Done client-side it is
 * a binary search costing `O(log n)` block fetches per lookup; the server spends those on its own
 * connection instead.
 *
 * @param serverUrl - The base URL of the CRISP server
 * @param timestamp - The unix timestamp to resolve
 * @returns The block at or before the timestamp, and that block's timestamp
 */
export const getBlockAtTimestamp = async (serverUrl: string, timestamp: bigint): Promise<{ blockNumber: bigint; timestamp: bigint }> => {
  const data = await postJson<{ block_number: number | string; timestamp: number | string }>(
    serverUrl,
    CRISP_SERVER_CHAIN_BLOCK_AT_TIMESTAMP_ENDPOINT,
    { timestamp: Number(timestamp) },
  )

  return { blockNumber: BigInt(data.block_number), timestamp: BigInt(data.timestamp) }
}

/**
 * The URL of the server's read-only JSON-RPC endpoint.
 *
 * Point a standard Ethereum client at this to read the allowlisted contracts without a
 * hosted-provider key. It serves reads only — transactions are signed and broadcast by the
 * user's wallet, which brings its own transport.
 *
 * @param serverUrl - The base URL of the CRISP server
 * @returns The JSON-RPC URL
 */
export const chainRpcUrl = (serverUrl: string): string => `${serverUrl.replace(/\/+$/, '')}/${CRISP_SERVER_CHAIN_RPC_ENDPOINT}`
