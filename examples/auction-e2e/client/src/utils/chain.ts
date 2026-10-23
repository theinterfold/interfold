// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { createPublicClient, http, type Chain, type PublicClient, type WalletClient } from 'viem'
import { anvil, sepolia } from 'viem/chains'
import { InterfoldSDK } from '@interfold/sdk'
import { PRESET } from '@interfold/auction'
import { CHAIN_ID, ENABLE_TEST_TOKEN_MINT_FLAG, FAUCET_ADDRESS, RPC_URL, getContractAddresses } from './env-config'

/** The chain the app runs on: `VITE_CHAIN_ID`, anvil (31337) when unset. Sepolia (11155111) is the other supported one. */
export function getChain(): Chain {
  const id = CHAIN_ID ? Number.parseInt(CHAIN_ID, 10) : anvil.id
  const supported = [anvil, sepolia].find((candidate) => candidate.id === id)
  if (!supported) throw new Error(`VITE_CHAIN_ID must be ${anvil.id} (anvil) or ${sepolia.id} (Sepolia), got "${CHAIN_ID}"`)
  return supported
}

/** `interfold print-env --vite` yields a WebSocket URL; the browser reads over HTTP polling, so map it back. */
function httpRpcUrl(): string {
  if (RPC_URL.startsWith('ws://')) return `http://${RPC_URL.slice('ws://'.length)}`
  if (RPC_URL.startsWith('wss://')) return `https://${RPC_URL.slice('wss://'.length)}`
  return RPC_URL
}

export const chain = getChain()
export const HTTP_RPC_URL = httpRpcUrl()

/**
 * How a user without fee tokens can get some on a test deployment: from a faucet contract when one is
 * configured, else by minting the mock token (always on anvil), else not at all.
 */
export const TEST_TOKEN_SOURCE: 'faucet' | 'mint' | null = FAUCET_ADDRESS
  ? 'faucet'
  : chain.id === anvil.id || ENABLE_TEST_TOKEN_MINT_FLAG
    ? 'mint'
    : null

export const publicClient: PublicClient = createPublicClient({ chain, transport: http(HTTP_RPC_URL) })

/**
 * An SDK client over the shared public client. With a wallet client it signs the fee approval and the
 * E3 request as the connected account; without one it only reads.
 */
export function createSdk(walletClient?: WalletClient): InterfoldSDK {
  const { interfold, ciphernodeRegistry, feeToken } = getContractAddresses()
  return new InterfoldSDK({
    publicClient,
    walletClient,
    chain,
    contracts: { interfold, ciphernodeRegistry, feeToken },
    thresholdBfvParamsPresetName: PRESET,
  })
}

let readSdk: InterfoldSDK | undefined

/** The read-only SDK client shared by the whole page. */
export function getReadSdk(): InterfoldSDK {
  readSdk ??= createSdk()
  return readSdk
}

const explorerBase = () => chain.blockExplorers?.default?.url

/** The block-explorer URL of a transaction, or `undefined` where the chain has no explorer (anvil). */
export function txExplorerUrl(txHash: string): string | undefined {
  const base = explorerBase()
  return base ? `${base}/tx/${txHash}` : undefined
}

/** The block-explorer URL of an address (account or contract), or `undefined` where the chain has no explorer. */
export function addressExplorerUrl(address: string): string | undefined {
  const base = explorerBase()
  return base ? `${base}/address/${address}` : undefined
}
