// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useAccount } from 'wagmi'
import { chain } from '@/utils/chain'

export interface Wallet {
  address: `0x${string}` | undefined
  isConnected: boolean
  /** Connected, but to another chain than the app's. Writes would be signed for the wrong network. */
  wrongChain: boolean
  /** Connected to the app's chain: the wallet can send transactions here. */
  ready: boolean
}

export function useWallet(): Wallet {
  const { address, isConnected, chainId } = useAccount()
  const wrongChain = isConnected && chainId !== chain.id
  return { address, isConnected, wrongChain, ready: isConnected && !wrongChain }
}
