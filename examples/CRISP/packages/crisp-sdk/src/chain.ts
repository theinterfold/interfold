// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { createPublicClient, http } from 'viem'
import { localhost, sepolia } from 'viem/chains'

import type { PublicClient } from 'viem'

/**
 * Create a public client for one of the chains supported by CRISP
 * @param chainId - The chain ID of the network
 * @returns The public client for the given chain
 */
export const getPublicClient = (chainId: number): PublicClient => {
  let chain
  switch (chainId) {
    case 11155111:
      chain = sepolia
      break
    case 31337:
      chain = localhost
      break
    default:
      throw new Error('Unsupported chainId')
  }

  return createPublicClient({
    transport: http(),
    chain,
  })
}
