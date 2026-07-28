// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { parseAbi } from 'viem'

import { CRISP_SERVER_PREVIOUS_CIPHERTEXT_ENDPOINT } from './constants'
import { getRoundStateLite } from './api'
import { getPublicClient } from './chain'

import type { CreditMode, OnChainRoundData, RoundDetails, TokenDetails } from './types'

/**
 * Get the details of a specific round in a camelCase convenience format
 * @param serverUrl - The base URL of the CRISP server
 * @param e3Id - The e3Id of the round
 * @returns The round details
 */
export const getRoundDetails = async (serverUrl: string, e3Id: number): Promise<RoundDetails> => {
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
export const getRoundTokenDetails = async (serverUrl: string, e3Id: number): Promise<TokenDetails> => {
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
 * @returns The on chain round data
 */
export const getOnChainRoundData = async (programAddress: string, e3Id: number, chainId: number): Promise<OnChainRoundData> => {
  const publicClient = getPublicClient(chainId)

  const [merkleRoot, paramsHash, numOptions, creditMode, inputRoot, numberOfVotes] = await publicClient.readContract({
    address: programAddress as `0x${string}`,
    abi: parseAbi([
      'function getRoundData(uint256 e3Id) view returns (uint256 merkleRoot, bytes32 paramsHash, uint256 numOptions, uint8 creditMode, uint256 inputRoot, uint40 numberOfVotes)',
    ]),
    functionName: 'getRoundData',
    args: [BigInt(e3Id)],
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
 * Get the previous ciphertext for a slot from the CRISP server.
 * Returns undefined when the slot is empty (404).
 *
 * @param serverUrl - The base URL of the CRISP server
 * @param e3Id - The e3Id of the round
 * @param address - The address of the slot
 * @returns The previous ciphertext for the slot, or undefined if the slot is empty
 */
export const getPreviousCiphertext = async (serverUrl: string, e3Id: number, address: string): Promise<Uint8Array | undefined> => {
  const response = await fetch(`${serverUrl}/${CRISP_SERVER_PREVIOUS_CIPHERTEXT_ENDPOINT}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ round_id: e3Id, address }),
  })

  if (response.status === 404) {
    return undefined
  }

  if (!response.ok) {
    throw new Error(`Failed to fetch previous ciphertext: ${response.statusText}`)
  }

  const data = await response.json()

  return new Uint8Array(data.ciphertext)
}
