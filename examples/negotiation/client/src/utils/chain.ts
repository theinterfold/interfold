// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import {
  createPublicClient,
  http,
  publicActions,
  type Address,
  type Chain,
  type PublicClient,
  type TransactionReceipt,
  type WalletClient,
} from 'viem'
import { anvil, sepolia } from 'viem/chains'
import { InterfoldSDK } from '@interfold/sdk'
import { PRESET } from '@interfold/negotiation'
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

/** Whether the mock fee token of this deployment has a public `mint` (always on anvil). */
const CAN_MINT_TEST_TOKENS = chain.id === anvil.id || ENABLE_TEST_TOKEN_MINT_FLAG

/**
 * How a user without fee tokens can get some on a test deployment: from a faucet contract when one is
 * configured, else by minting the mock token (always on anvil), else not at all.
 */
export const TEST_TOKEN_SOURCE: 'faucet' | 'mint' | null = FAUCET_ADDRESS ? 'faucet' : CAN_MINT_TEST_TOKENS ? 'mint' : null

export const publicClient: PublicClient = createPublicClient({ chain, transport: http(HTTP_RPC_URL) })

const WALLET_SYNC_TIMEOUT_MS = 60_000
const WALLET_SYNC_POLL_MS = 500

/**
 * Wait for `receipt` to be mined, then until the wallet's own RPC view includes its block and the
 * account's nonce. A wallet picks the next nonce from its own block tracker, which can lag the app's
 * RPC by several blocks; a second transaction sent before it catches up reuses a spent nonce and fails
 * with "nonce too low". Call it between two transactions the wallet signs back to back.
 */
export async function waitForWalletSync(walletClient: WalletClient, account: Address, receipt: TransactionReceipt): Promise<void> {
  const expectedNonce = await publicClient.getTransactionCount({ address: account, blockTag: 'latest' })
  // Reads through the wallet's transport see what the wallet's own RPC sees.
  const wallet = walletClient.extend(publicActions)
  const deadline = Date.now() + WALLET_SYNC_TIMEOUT_MS
  for (;;) {
    const [walletBlock, walletNonce] = await Promise.all([
      wallet.getBlockNumber({ cacheTime: 0 }),
      wallet.getTransactionCount({ address: account, blockTag: 'latest' }),
    ])
    if (walletBlock >= receipt.blockNumber && walletNonce >= expectedNonce) return
    if (Date.now() > deadline) {
      throw new Error('The wallet has not seen the last transaction after 60 s. Reset its account activity and retry.')
    }
    await new Promise((resolve) => setTimeout(resolve, WALLET_SYNC_POLL_MS))
  }
}

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
