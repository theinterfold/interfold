// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { CRISP_SERVER_TOKEN_TREE_ENDPOINT } from './constants'

import { parseAbi } from 'viem'

import { getPublicClient } from './chain'

/**
 * Get the merkle tree data from the CRISP server
 * @param serverUrl - The base URL of the CRISP server
 * @param e3Id - The e3Id of the round
 */
export const getTreeData = async (serverUrl: string, e3Id: number): Promise<bigint[]> => {
  const response = await fetch(`${serverUrl}/${CRISP_SERVER_TOKEN_TREE_ENDPOINT}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ round_id: e3Id }),
  })

  const hashes = (await response.json()) as string[]

  // Convert hex strings to BigInts
  return hashes.map((hash) => {
    // Ensure the hash is treated as a hex string
    if (!hash.startsWith('0x')) {
      return BigInt('0x' + hash)
    }
    return BigInt(hash)
  })
}

/**
 * Get the token balance at a specific block for a given address
 * @param voterAddress - The address of the voter
 * @param tokenAddress - The address of the token contract
 * @param snapshotBlock - The block number at which to get the balance
 * @param chainId - The chain ID of the network
 * @returns The token balance as a bigint
 */
export const getBalanceAt = async (voterAddress: string, tokenAddress: string, snapshotBlock: number, chainId: number): Promise<bigint> => {
  const publicClient = getPublicClient(chainId)

  const balance = (await publicClient.readContract({
    address: tokenAddress as `0x${string}`,
    abi: parseAbi(['function getPastVotes(address, uint256) view returns (uint256)']),
    functionName: 'getPastVotes',
    args: [voterAddress as `0x${string}`, BigInt(snapshotBlock)],
  })) as bigint

  return balance
}

/**
 * Get the total supply of a ERC20Votes Token at a specific block
 * @param tokenAddress The token address to query
 * @param snapshotBlock The block number at which to get the total supply
 * @param chainId The chain ID of the network
 * @returns The total supply as a bigint
 */
export const getTotalSupplyAt = async (tokenAddress: string, snapshotBlock: number, chainId: number): Promise<bigint> => {
  const publicClient = getPublicClient(chainId)

  const totalSupply = (await publicClient.readContract({
    address: tokenAddress as `0x${string}`,
    abi: parseAbi(['function getPastTotalSupply(uint256) view returns (uint256)']),
    functionName: 'getPastTotalSupply',
    args: [BigInt(snapshotBlock)],
  })) as bigint

  return totalSupply
}
