// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { CRISP_SERVER_STATE_LITE_ENDPOINT, CRISP_SERVER_PREVIOUS_CIPHERTEXT_ENDPOINT } from './constants'

import type { RoundDetailsResponse, RoundDetails, TokenDetails } from './types'

/**
 * Get the details of a specific round
 */
export const getRoundDetails = async (serverUrl: string, e3Id: number): Promise<RoundDetails> => {
  const response = await fetch(`${serverUrl}/${CRISP_SERVER_STATE_LITE_ENDPOINT}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ round_id: e3Id }),
  })

  const data = (await response.json()) as RoundDetailsResponse

  return {
    e3Id: BigInt(data.id),
    tokenAddress: data.token_address,
    balanceThreshold: BigInt(data.balance_threshold),
    chainId: BigInt(data.chain_id),
    interfoldAddress: data.interfold_address,
    status: data.status,
    voteCount: BigInt(data.vote_count),
    startTime: BigInt(data.start_time),
    duration: BigInt(data.duration),
    expiration: BigInt(data.expiration),
    startBlock: BigInt(data.start_block),
    committeePublicKey: data.committee_public_key,
    emojis: data.emojis,
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
    snapshotBlock: roundDetails.startBlock,
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
