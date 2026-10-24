// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { type Address, type WalletClient, formatUnits, parseAbi, parseUnits } from 'viem'
import { publicClient } from './chain'

/** What the app calls on the sale token, the payment token and the fee token. `mint` and the permit parts exist on the mocks only. */
export const erc20Abi = parseAbi([
  'function name() view returns (string)',
  'function symbol() view returns (string)',
  'function decimals() view returns (uint8)',
  'function balanceOf(address) view returns (uint256)',
  'function allowance(address owner, address spender) view returns (uint256)',
  'function approve(address spender, uint256 value) returns (bool)',
  'function mint(address to, uint256 amount)',
  'function nonces(address owner) view returns (uint256)',
  'function DOMAIN_SEPARATOR() view returns (bytes32)',
  'function eip712Domain() view returns (bytes1 fields, string name, string version, uint256 chainId, address verifyingContract, bytes32 salt, uint256[] extensions)',
])

export interface TokenInfo {
  address: Address
  symbol: string
  decimals: number
}

const cache = new Map<string, Promise<TokenInfo>>()

/** The symbol and decimals of an ERC-20, read once. Rejects when `address` is no ERC-20. */
export function readTokenInfo(address: Address): Promise<TokenInfo> {
  const key = address.toLowerCase()
  let info = cache.get(key)
  if (!info) {
    const read = { address, abi: erc20Abi } as const
    info = Promise.all([
      publicClient.readContract({ ...read, functionName: 'symbol' }),
      publicClient.readContract({ ...read, functionName: 'decimals' }),
    ]).then(([symbol, decimals]) => ({ address, symbol, decimals }))
    cache.set(key, info)
    // A failed read must not stay cached.
    info.catch(() => cache.delete(key))
  }
  return info
}

export const balanceOf = (token: Address, account: Address): Promise<bigint> =>
  publicClient.readContract({ address: token, abi: erc20Abi, functionName: 'balanceOf', args: [account] })

export const allowanceOf = (token: Address, owner: Address, spender: Address): Promise<bigint> =>
  publicClient.readContract({ address: token, abi: erc20Abi, functionName: 'allowance', args: [owner, spender] })

/** `amount` base units as a decimal string with digit grouping, trimmed of trailing zeros. */
export function formatAmount(amount: bigint, decimals: number, maxFraction = 6): string {
  const [whole, fraction = ''] = formatUnits(amount, decimals).split('.')
  const kept = fraction.slice(0, maxFraction).replace(/0+$/, '')
  const grouped = BigInt(whole).toLocaleString('en-US')
  return kept === '' ? grouped : `${grouped}.${kept}`
}

/** A typed decimal as base units, or `null` when it is no amount of at most `decimals` places. */
export function parseAmount(text: string, decimals: number): bigint | null {
  const trimmed = text.trim()
  if (!/^\d+(\.\d*)?$|^\.\d+$/.test(trimmed)) return null
  const [, fraction = ''] = trimmed.split('.')
  if (fraction.length > decimals) return null
  return parseUnits(trimmed.startsWith('.') ? `0${trimmed}` : trimmed, decimals)
}

/** Send `mint(account, amount)` on a mock token and wait for it. */
export async function mintTestTokens(walletClient: WalletClient, token: Address, account: Address, amount: bigint): Promise<void> {
  const { request } = await publicClient.simulateContract({
    address: token,
    abi: erc20Abi,
    functionName: 'mint',
    args: [account, amount],
    account,
  })
  const hash = await walletClient.writeContract(request)
  const receipt = await publicClient.waitForTransactionReceipt({ hash })
  if (receipt.status !== 'success') throw new Error('The mint transaction reverted')
}

/** Send `approve(spender, amount)` and wait for it. */
export async function approveToken(
  walletClient: WalletClient,
  token: Address,
  owner: Address,
  spender: Address,
  amount: bigint,
): Promise<void> {
  const { request } = await publicClient.simulateContract({
    address: token,
    abi: erc20Abi,
    functionName: 'approve',
    args: [spender, amount],
    account: owner,
  })
  const hash = await walletClient.writeContract(request)
  const receipt = await publicClient.waitForTransactionReceipt({ hash })
  if (receipt.status !== 'success') throw new Error('The approval transaction reverted')
}
