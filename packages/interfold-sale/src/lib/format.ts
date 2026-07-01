// SPDX-License-Identifier: LGPL-3.0-only

import { decodeBytes32String, encodeBytes32String, formatEther, formatUnits, getAddress, isHexString } from 'ethers'
import { ZERO } from '../constants'
import type { SaleDeployment } from '../types'

export function shortAddress(value?: string): string {
  if (!value) return '-'
  return `${value.slice(0, 6)}...${value.slice(-4)}`
}

export function explorerBase(chainId: number): string | undefined {
  if (chainId === 1) return 'https://etherscan.io'
  if (chainId === 11155111) return 'https://sepolia.etherscan.io'
  if (chainId === 8453) return 'https://basescan.org'
  if (chainId === 84532) return 'https://sepolia.basescan.org'
  return undefined
}

export function explorerLink(chainId: number, type: 'address' | 'tx', value: string): string | undefined {
  const base = explorerBase(chainId)
  return base ? `${base}/${type}/${value}` : undefined
}

export function currencyAddress(value?: string): string {
  if (!value || value.toUpperCase() === 'ETH' || value.toLowerCase() === ZERO) return ZERO
  return getAddress(value)
}

export function currencyDisplay(value?: string, symbol?: string): string {
  if (!value || value.toUpperCase() === 'ETH' || value.toLowerCase() === ZERO) return symbol ?? 'ETH'
  return symbol ? `${symbol} · ${shortAddress(value)}` : shortAddress(value)
}

export function networkLabel(chainId: number): string {
  if (chainId === 1) return 'Ethereum mainnet'
  if (chainId === 11155111) return 'Sepolia'
  return `Chain ${chainId}`
}

export function saleDisplayName(deployment: SaleDeployment): string {
  const raw = deployment.name.toLowerCase()
  if (deployment.chainId === 1 || raw.includes('mainnet')) return 'FOLD Launch Auction'
  if (raw.includes('dry') || raw.includes('test') || deployment.chainId === 11155111) return 'Sepolia CCA Dry Run'
  return 'FOLD Continuous Clearing Auction'
}

export function saleMetaLabel(deployment: SaleDeployment): string {
  return `${networkLabel(deployment.chainId)} · ${deployment.ccaVersion} · ${deployment.saleLabel}`
}

export function deploymentRunLabel(deployment: SaleDeployment): string {
  const timestamp = deployment.name.match(/(\d{8,})$/)?.[1]
  if (timestamp) return `Run ${timestamp.slice(-6)}`
  return deployment.name.length > 28 ? `${deployment.name.slice(0, 25)}...` : deployment.name
}

export function formatTokenAmount(value?: bigint, digits = 4): string {
  if (value === undefined) return '-'
  const raw = formatEther(value)
  const [head, tail = ''] = raw.split('.')
  const trimmed = tail.slice(0, digits).replace(/0+$/, '')
  return trimmed ? `${head}.${trimmed}` : head
}

export function formatAmount(value?: bigint, decimals = 18, digits = 4): string {
  if (value === undefined) return '-'
  const raw = formatUnits(value, decimals)
  const [head, tail = ''] = raw.split('.')
  const trimmed = tail.slice(0, digits).replace(/0+$/, '')
  return trimmed ? `${head}.${trimmed}` : head
}

export function formatIntegerCompact(value?: bigint): string {
  if (value === undefined) return '-'
  const raw = value.toString()
  if (raw.length <= 9) return raw
  const suffixes = [
    { value: 1_000_000_000_000n, label: 'T' },
    { value: 1_000_000_000n, label: 'B' },
    { value: 1_000_000n, label: 'M' },
    { value: 1_000n, label: 'K' },
  ]
  const unit = suffixes.find((item) => value >= item.value)
  if (!unit) return raw
  const whole = value / unit.value
  const fraction = ((value % unit.value) * 10n) / unit.value
  return fraction > 0n ? `${whole}.${fraction}${unit.label}` : `${whole}${unit.label}`
}

export function formatDate(seconds?: string | bigint): string {
  if (seconds === undefined || seconds === '') return '-'
  const date = new Date(Number(seconds) * 1000)
  return Number.isNaN(date.getTime()) ? '-' : date.toLocaleString()
}

export function normalizeAddress(value: string): string {
  return getAddress(value.trim())
}

export function bytes32FromInput(value: string): string {
  const trimmed = value.trim()
  if (isHexString(trimmed, 32)) return trimmed
  return encodeBytes32String(trimmed)
}

export function bytes32Label(value: string): string {
  try {
    const decoded = decodeBytes32String(value)
    return decoded || value
  } catch {
    return value
  }
}

export function readableError(error: unknown): string {
  if (!(error instanceof Error)) return 'Transaction failed'
  const short = error.message.split('\n')[0]
  return short.length > 220 ? `${short.slice(0, 220)}...` : short
}
