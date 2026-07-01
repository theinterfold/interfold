// SPDX-License-Identifier: LGPL-3.0-only

import { AbiCoder, BrowserProvider, Contract, JsonRpcProvider, getAddress } from 'ethers'
import { ERC20_ABI } from '../abis'
import { ZERO } from '../constants'
import type { AuctionConfig, AuctionStep, PredicateAttestationResponse, SaleDeployment } from '../types'
import { currencyAddress } from './format'

const PREDICATE_ATTESTATION_TUPLE = 'tuple(string uuid,uint256 expiration,address attester,bytes signature)'
const predicateAbi = AbiCoder.defaultAbiCoder()

export function predicateChain(chainId: number): string {
  if (chainId === 1) return 'ethereum'
  if (chainId === 11155111) return 'sepolia'
  if (chainId === 8453) return 'base'
  if (chainId === 84532) return 'base_sepolia'
  return String(chainId)
}

export function predicateHookAddress(deployment: SaleDeployment, auctionConfig?: AuctionConfig): string | undefined {
  const hook = deployment.validationHook ?? auctionConfig?.validationHook
  if (!hook || hook.toLowerCase() === ZERO) return undefined
  return hook
}

export async function predicateHookData(deployment: SaleDeployment, account: string): Promise<string> {
  const hook = predicateHookAddress(deployment, deployment.auctionConfig)
  if (!hook) return '0x'

  const endpoint = import.meta.env.VITE_PREDICATE_ATTESTATION_URL ?? '/api/predicate/attestation'
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      userAddress: account,
      contractAddress: hook,
      chain: predicateChain(deployment.chainId),
    }),
  })
  const result = (await response.json().catch(() => ({}))) as PredicateAttestationResponse
  if (!response.ok || !result.is_compliant || !result.attestation) {
    const reason = result.reason?.message ?? result.error ?? response.statusText
    throw new Error(`Predicate attestation failed: ${reason}`)
  }
  const { uuid, expiration, attester, signature } = result.attestation
  return predicateAbi.encode([PREDICATE_ATTESTATION_TUPLE], [[uuid, BigInt(expiration), getAddress(attester), signature]])
}

export function blockProgress(current: bigint | undefined, config?: AuctionConfig): number {
  if (!current || !config) return 0
  const start = BigInt(config.startBlock)
  const end = BigInt(config.endBlock)
  if (end <= start) return current >= end ? 100 : 0
  if (current <= start) return 0
  if (current >= end) return 100
  const scaled = ((current - start) * 10_000n) / (end - start)
  return Number(scaled) / 100
}

export function blockDistanceLabel(current: bigint | undefined, target?: string): string {
  if (!current || !target) return '-'
  const delta = BigInt(target) - current
  if (delta === 0n) return 'current block'
  if (delta > 0n) return `${delta.toString()} blocks away`
  return `${(-delta).toString()} blocks ago`
}

export function statusLine(status: string, current: bigint | undefined, config?: AuctionConfig): string {
  if (!config) return '-'
  if (status === 'Scheduled') return `Starts ${blockDistanceLabel(current, config.startBlock)}`
  if (status === 'Live') return `Ends ${blockDistanceLabel(current, config.endBlock)}`
  if (status === 'Settling') return `Claims open ${blockDistanceLabel(current, config.claimBlock)}`
  if (status === 'Claim Open') return 'Claims are open'
  return 'Reading auction state'
}

export function decodeAuctionSchedule(encoded?: string): AuctionStep[] {
  if (!encoded || !/^0x([0-9a-fA-F]{16})+$/.test(encoded)) return []
  const steps: AuctionStep[] = []
  let cursor = 0n
  for (let offset = 2; offset < encoded.length; offset += 16) {
    const packed = BigInt(`0x${encoded.slice(offset, offset + 16)}`)
    const mps = packed >> 40n
    const blockDelta = packed & ((1n << 40n) - 1n)
    const supply = mps * blockDelta
    steps.push({
      index: steps.length + 1,
      mps,
      blockDelta,
      supply,
      startOffset: cursor,
      endOffset: cursor + blockDelta,
    })
    cursor += blockDelta
  }
  return steps
}

export function ccaStatus(current: bigint | undefined, config?: AuctionConfig): string {
  if (!current || !config) return 'Loading'
  const start = BigInt(config.startBlock)
  const end = BigInt(config.endBlock)
  const claim = BigInt(config.claimBlock)
  if (current < start) return 'Scheduled'
  if (current <= end) return 'Live'
  if (current < claim) return 'Settling'
  return 'Claim Open'
}

export function ccaStatusIndex(current: bigint | undefined, config?: AuctionConfig): number {
  if (!current || !config) return 0
  if (current < BigInt(config.startBlock)) return 0
  if (current <= BigInt(config.endBlock)) return 1
  if (current < BigInt(config.claimBlock)) return 2
  return 3
}

export async function readCurrencyState(provider: JsonRpcProvider | BrowserProvider, rawCurrency: string, account?: string) {
  const address = currencyAddress(rawCurrency)
  if (address === ZERO) {
    return {
      symbol: 'ETH',
      decimals: 18,
      balance: account ? await provider.getBalance(account) : 0n,
    }
  }

  const currency = new Contract(address, ERC20_ABI, provider)
  const [symbol, decimals, balance] = await Promise.all([
    currency.symbol().catch(() => 'ERC20') as Promise<string>,
    currency.decimals().catch(() => 18) as Promise<number>,
    account ? (currency.balanceOf(account) as Promise<bigint>) : Promise.resolve(0n),
  ])
  return { symbol, decimals: Number(decimals), balance }
}
