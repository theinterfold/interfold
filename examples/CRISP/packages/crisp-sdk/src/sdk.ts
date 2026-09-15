// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import {
  broadcastVote,
  chainRpcUrl,
  getBlockAtTimestamp,
  getChainHead,
  getIndexedLogs,
  readContracts,
  getAllRoundResults,
  getCurrentRound,
  getEligibleAddresses,
  getRoundCiphertext,
  getRoundPublicKey,
  getRoundResult,
  getRoundStateLite,
  getTokenHolderHashes,
  getVoteAvailability,
  getVoteStatus,
  requestNewRound,
} from './api'
import { getOnChainRoundData, getOnchainVotingPower, getPreviousCiphertext, getRoundDetails, getRoundTokenDetails } from './state'
import { finishBallotProof, finishMaskProof, prepareBallot } from './vote'

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
  OnChainRoundData,
  PrepareBallotRequest,
  PreparedBallot,
  ProofData,
  RoundDetails,
  SlotHead,
  TokenDetails,
  TokenHolder,
  VoteStatusResponse,
  WebResultResponse,
} from './types'

/**
 * Pass as the SDK's `rpcUrl` to read the chain through the CRISP server's own `/chain/rpc` route.
 *
 * A sentinel rather than a boolean flag so the parameter keeps one meaning — "where chain reads
 * go" — whether that is a URL you supply or the server you are already talking to.
 */
export const SERVER_RPC = 'server' as const

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
   * Endpoint used for direct chain reads, or `undefined` to use viem's default public RPC.
   */
  private rpcUrl: string | undefined

  /**
   * Create a new instance.
   *
   * @param serverUrl - The base URL of the CRISP server
   * @param rpcUrl - Endpoint for direct chain reads. Omit (or pass `null`) to keep viem's default
   *                 public RPC. Pass {@link SERVER_RPC} to read through the CRISP server's own
   *                 `/chain/rpc` route instead of a third-party endpoint. Any other string is used
   *                 as the endpoint URL directly.
   *
   * Routing through the server is opt-in rather than the default because it is a change of
   * transport, not a tuning knob: a caller who merely upgrades this package would have every chain
   * read redirected to a route their deployed server may not have — or may not be configured to
   * serve the contracts being read — turning a version bump into an outage.
   */
  constructor(serverUrl: string, rpcUrl?: string | null) {
    this.serverUrl = serverUrl
    this.rpcUrl = rpcUrl === SERVER_RPC ? chainRpcUrl(serverUrl) : (rpcUrl ?? undefined)
  }

  /**
   * Phase one: encrypt a ballot, before the voter signs anything.
   *
   * A ballot has to be encrypted before it can be signed, because the digest binds the ciphertext.
   * Take `ctCommitment` from the result, read the digest from
   * `CRISPProgram.ballotDigest(e3Id, slot, ctCommitment)`, have the voter sign it, then call
   * {@link finishBallot}.
   *
   * Masks and real votes take the same path. This method calls the same server API
   * (previous-ciphertext) for both, so the server cannot infer the ballot type from the request
   * pattern, and the encryption is identical either way.
   *
   * @param request - The ballot to encrypt.
   * @returns A promise that resolves to the prepared ballot.
   */
  async prepareBallot(request: PrepareBallotRequest): Promise<PreparedBallot> {
    const head = await getPreviousCiphertext(this.serverUrl, request.e3Id, request.slotAddress)

    // Branched rather than spread conditionally. The two halves of a slot head only mean anything
    // together and the type models them as a pair, which a conditional spread widens back into two
    // independent optional fields — the exact shape the pair exists to rule out.
    return head ? prepareBallot({ ...request, previousCiphertext: head.ciphertext, previousIndex: head.index }) : prepareBallot(request)
  }

  /**
   * Phase two: prove a prepared ballot.
   *
   * A mask passes no signature and gets the placeholder. It still carries the same digest as a
   * real vote, because the contract computes the digest for every input.
   *
   * @param prepared - The output of {@link prepareBallot}.
   * @param digest - The digest read from `CRISPProgram.ballotDigest`.
   * @param signature - The voter signature, omitted for a mask.
   * @returns A promise that resolves to the generated proof data.
   */
  async finishBallot(prepared: PreparedBallot, digest: `0x${string}`, signature?: `0x${string}`): Promise<ProofData> {
    return signature ? finishBallotProof(prepared, digest, signature) : finishMaskProof(prepared, digest)
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
  async getRoundPublicKey(e3Id: bigint): Promise<Uint8Array> {
    return getRoundPublicKey(this.serverUrl, e3Id)
  }

  /**
   * Get the ciphertext output for a given round.
   * @param e3Id - The e3Id of the round
   * @returns The ciphertext output bytes
   */
  async getRoundCiphertext(e3Id: bigint): Promise<Uint8Array> {
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
   * @param request - The vote request (round id and hex encoded proof)
   * @returns The broadcast result, including the transaction hash on success
   */
  async broadcastVote(request: BroadcastVoteRequest): Promise<BroadcastVoteResponse> {
    return broadcastVote(this.serverUrl, request)
  }

  /**
   * Read a durable availability job without waiting for Avail or VectorX.
   * @param jobId - The job id returned by `broadcastVote`
   * @returns The job's current commitment or availability state
   */
  async getVoteAvailability(jobId: string): Promise<BroadcastVoteResponse> {
    return getVoteAvailability(this.serverUrl, jobId)
  }

  /**
   * Get the vote status for an address in a specific round.
   * @param e3Id - The e3Id of the round
   * @param address - The voter address
   * @returns The vote status for the address
   */
  async getVoteStatus(e3Id: bigint, address: string): Promise<VoteStatusResponse> {
    return getVoteStatus(this.serverUrl, e3Id, address)
  }

  /**
   * Get the result for a given round.
   * @param e3Id - The e3Id of the round
   * @returns The round result (tally, emojis, total votes, end time and requester)
   */
  async getRoundResult(e3Id: bigint): Promise<WebResultResponse> {
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
  async getRoundStateLite(e3Id: bigint): Promise<E3StateLiteResponse> {
    return getRoundStateLite(this.serverUrl, e3Id)
  }

  /**
   * Get the details of a specific round in a camelCase convenience format.
   * @param e3Id - The e3Id of the round
   * @returns The round details
   */
  async getRoundDetails(e3Id: bigint): Promise<RoundDetails> {
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
  async getOnChainRoundData(programAddress: string, e3Id: bigint, chainId?: number): Promise<OnChainRoundData> {
    const chain = chainId ?? Number((await getRoundDetails(this.serverUrl, e3Id)).chainId)

    return getOnChainRoundData(programAddress, e3Id, chain, this.rpcUrl)
  }

  /**
   * Get the voting power a slot may spend in a `CensusMode.ONCHAIN` round, read from the CRISP
   * program through this instance's configured endpoint.
   *
   * @param programAddress - The CRISP program address
   * @param e3Id - The e3Id of the round
   * @param slot - The slot address the ballot is written to
   * @param chainId - The chain the program is deployed on; looked up on the server when omitted
   * @returns The spendable voting power in ballot units
   */
  async getOnchainVotingPower(programAddress: string, e3Id: bigint, slot: string, chainId?: number): Promise<bigint> {
    const chain = chainId ?? Number((await getRoundDetails(this.serverUrl, e3Id)).chainId)

    return getOnchainVotingPower(programAddress, e3Id, slot, chain, this.rpcUrl)
  }

  /**
   * Get the token address, balance threshold and snapshot block for a specific round.
   * @param e3Id - The e3Id of the round
   * @returns The token details
   */
  async getRoundTokenDetails(e3Id: bigint): Promise<TokenDetails> {
    return getRoundTokenDetails(this.serverUrl, e3Id)
  }

  /**
   * Get the token holder hashes (hash(address, balance)) for a given round.
   * These are the Merkle tree leaves used for eligibility proofs.
   * @param e3Id - The e3Id of the round
   * @returns The list of token holder hashes
   */
  async getTokenHolderHashes(e3Id: bigint): Promise<string[]> {
    return getTokenHolderHashes(this.serverUrl, e3Id)
  }

  /**
   * Get the eligible addresses and their balances for a given round.
   * @param e3Id - The e3Id of the round
   * @returns The list of eligible token holders
   */
  async getEligibleAddresses(e3Id: bigint): Promise<TokenHolder[]> {
    return getEligibleAddresses(this.serverUrl, e3Id)
  }

  /**
   * Get the chain head (block number, timestamp, chain id) as seen by the server.
   * @returns The current head
   */
  async getChainHead(): Promise<ChainHead> {
    return getChainHead(this.serverUrl)
  }

  /**
   * Read allowlisted contracts through the server, batched, without a provider key of your own.
   * @param calls - The calls to perform, in order
   * @returns One result per call, in the same order
   */
  async readContracts(calls: ContractRead[]): Promise<ContractReadResult[]> {
    return readContracts(this.serverUrl, calls)
  }

  /**
   * Query logs for an allowlisted contract over an arbitrary block range. The server windows the
   * range for you, so no chunking is needed on this side.
   * @param query - The log query
   * @returns The matching logs, ordered by block and log index
   */
  async getLogs(query: LogQuery): Promise<IndexedLog[]> {
    return getIndexedLogs(this.serverUrl, query)
  }

  /**
   * Resolve a unix timestamp to the last block at or before it.
   * @param timestamp - The unix timestamp
   * @returns The block number and its timestamp
   */
  async getBlockAtTimestamp(timestamp: bigint): Promise<{ blockNumber: bigint; timestamp: bigint }> {
    return getBlockAtTimestamp(this.serverUrl, timestamp)
  }

  /**
   * The server's read-only JSON-RPC URL, for pointing a standard Ethereum client at.
   * @returns The JSON-RPC URL
   */
  chainRpcUrl(): string {
    return chainRpcUrl(this.serverUrl)
  }

  /**
   * Get the previous ciphertext input for a slot address in a given round.
   * @param e3Id - The e3Id of the round
   * @param address - The address of the slot
   * @returns The slot head and its tree index, or undefined if the slot holds nothing usable
   */
  async getPreviousCiphertext(e3Id: bigint, address: string): Promise<SlotHead | undefined> {
    return getPreviousCiphertext(this.serverUrl, e3Id, address)
  }
}
