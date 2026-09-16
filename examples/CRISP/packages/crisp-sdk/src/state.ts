// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { parseAbi } from 'viem'

import { CRISP_SERVER_PREVIOUS_CIPHERTEXT_ENDPOINT, CRISP_SERVER_SLOT_ENTRIES_ENDPOINT } from './constants'
import { getRoundStateLite } from './api'
import { getPublicClient } from './chain'

import type { CreditMode, OnChainRoundData, RoundDetails, SlotEntry, SlotHead, TokenDetails } from './types'

/**
 * Get the details of a specific round in a camelCase convenience format
 * @param serverUrl - The base URL of the CRISP server
 * @param e3Id - The e3Id of the round
 * @returns The round details
 */
export const getRoundDetails = async (serverUrl: string, e3Id: bigint): Promise<RoundDetails> => {
  const data = await getRoundStateLite(serverUrl, e3Id)

  return {
    e3Id: BigInt(data.id),
    tokenAddress: data.token_address,
    balanceThreshold: BigInt(data.balance_threshold),
    chainId: BigInt(data.chain_id),
    interfoldAddress: data.interfold_address,
    status: data.status,
    voteCount: BigInt(data.vote_count),
    startTime: BigInt(data.start_time),
    endTime: BigInt(data.end_time),
    startBlock: BigInt(data.start_block),
    snapshotBlock: BigInt(data.snapshot_block),
    committeePublicKey: new Uint8Array(data.committee_public_key),
    emojis: data.emojis,
    numOptions: BigInt(data.num_options),
    requester: data.requester,
    creditMode: data.credit_mode,
    credits: data.credits !== null ? BigInt(data.credits) : undefined,
  }
}

/**
 * Get the token address, balance threshold and snapshot block for a specific round
 * @param serverUrl - The base URL of the CRISP server
 * @param e3Id - The e3Id of the round
 * @returns The token address, balance threshold and snapshot block
 */
export const getRoundTokenDetails = async (serverUrl: string, e3Id: bigint): Promise<TokenDetails> => {
  const roundDetails = await getRoundDetails(serverUrl, e3Id)
  return {
    tokenAddress: roundDetails.tokenAddress,
    threshold: roundDetails.balanceThreshold,
    snapshotBlock: roundDetails.snapshotBlock,
  }
}

/**
 * Get the round data stored in the CRISPProgram contract, such as the merkle root
 * of the census and the merkle root of the encrypted votes published so far.
 *
 * Unlike {@link getRoundDetails}, this reads directly from the chain and so does not
 * depend on the CRISP server.
 *
 * @param programAddress - The address of the CRISPProgram contract
 * @param e3Id - The e3Id of the round
 * @param chainId - The chain ID of the network the program is deployed on
 * @param rpcUrl - Endpoint to read through. Omitted, viem's default public RPC for the chain is
 *                 used — a third-party service this SDK cannot observe or rate-limit.
 * @returns The on chain round data
 */
export const getOnChainRoundData = async (
  programAddress: string,
  e3Id: bigint,
  chainId: number,
  rpcUrl?: string,
): Promise<OnChainRoundData> => {
  const publicClient = getPublicClient(chainId, rpcUrl)

  const [merkleRoot, paramsHash, numOptions, creditMode, inputRoot, numberOfVotes] = await publicClient.readContract({
    address: programAddress as `0x${string}`,
    abi: parseAbi([
      'function getRoundData(uint256 e3Id) view returns (uint256 merkleRoot, bytes32 paramsHash, uint256 numOptions, uint8 creditMode, uint256 inputRoot, uint40 numberOfVotes)',
    ]),
    functionName: 'getRoundData',
    args: [e3Id],
  })

  return {
    merkleRoot,
    paramsHash,
    numOptions,
    creditMode: creditMode as CreditMode,
    inputRoot,
    numberOfVotes: BigInt(numberOfVotes),
  }
}

/**
 * Get the voting power a slot may spend in a `CensusMode.ONCHAIN` round, in ballot units.
 *
 * Read from the CRISP program rather than derived here. The contract scales raw token power by a
 * per-round divisor before handing it to the circuit as public input 4, and it is the same
 * contract that verifies the proof — so recomputing the value client-side would mean re-deriving
 * the round's snapshot, its divisor and the rounding, and any drift surfaces only as an opaque
 * verifier failure.
 *
 * @param programAddress - The CRISP program address
 * @param e3Id - The e3Id of the round
 * @param slot - The slot address the ballot is written to
 * @param chainId - The chain the program is deployed on
 * @param rpcUrl - Endpoint to read through; see {@link getOnChainRoundData}.
 * @returns The spendable voting power in ballot units, or 0 for a round that is not ONCHAIN
 */
export const getOnchainVotingPower = async (
  programAddress: string,
  e3Id: bigint,
  slot: string,
  chainId: number,
  rpcUrl?: string,
): Promise<bigint> => {
  const publicClient = getPublicClient(chainId, rpcUrl)

  return publicClient.readContract({
    address: programAddress as `0x${string}`,
    abi: parseAbi(['function votingPowerOf(uint256 e3Id, address slot) view returns (uint256)']),
    functionName: 'votingPowerOf',
    args: [e3Id, slot as `0x${string}`],
  })
}

/**
 * Get the previous ciphertext for a slot from the CRISP server.
 * Returns undefined when the slot is empty (404).
 *
 * @param serverUrl - The base URL of the CRISP server
 * @param e3Id - The e3Id of the round
 * @param address - The address of the slot
 * @returns The end of the slot's chain of usable entries and its tree index, or undefined when the
 *          slot holds nothing usable. The index is what a new input names as its parent.
 */
export const getPreviousCiphertext = async (serverUrl: string, e3Id: bigint, address: string): Promise<SlotHead | undefined> => {
  const response = await fetch(`${serverUrl}/${CRISP_SERVER_PREVIOUS_CIPHERTEXT_ENDPOINT}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ round_id: e3Id.toString(), address }),
  })

  if (response.status === 404) {
    return undefined
  }

  if (!response.ok) {
    throw new Error(`Failed to fetch previous ciphertext: ${response.statusText}`)
  }

  const data = await response.json()

  return { ciphertext: new Uint8Array(data.ciphertext), index: Number(data.index) }
}

/**
 * Get every entry published to a slot, without the server's own view of which one holds it.
 *
 * The companion to {@link getPreviousCiphertext}: that endpoint reports the server's answer, this
 * one reports the entries the answer was derived from. A caller that resolves the head itself
 * needs these, because an entry's bytes are the only part of an input that is not on chain —
 * `InputPublished` carries the Avail coordinates rather than the ciphertext.
 *
 * @param serverUrl - The base URL of the CRISP server
 * @param e3Id - The e3Id of the round
 * @param address - The address of the slot
 * @returns Every entry of the slot in on-chain index order, which is empty when the slot has none.
 */
export const getSlotEntries = async (serverUrl: string, e3Id: bigint, address: string): Promise<SlotEntry[]> => {
  const response = await fetch(`${serverUrl}/${CRISP_SERVER_SLOT_ENTRIES_ENDPOINT}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ round_id: e3Id.toString(), address }),
  })

  if (!response.ok) {
    throw new Error(`Failed to fetch slot entries: ${response.statusText}`)
  }

  const data = await response.json()

  return (data.entries ?? []).map((entry: { ciphertext: number[]; index: number | string }) => ({
    ciphertext: new Uint8Array(entry.ciphertext),
    index: Number(entry.index),
  }))
}
