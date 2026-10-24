// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { zeroAddress } from 'viem'
import { E3Stage, FailureReason } from '@interfold/sdk'
import { type PriceList, readPriceList } from '@interfold/sealed-cca'
import { SealedCcaProgram__factory } from '@contract-types/factories/contracts/SealedCcaProgram__factory'
import { getContractAddresses } from './env-config'
import { scanLogs } from './logs'
import { getReadSdk, publicClient } from './chain'
import { type TokenInfo, formatAmount, readTokenInfo } from './tokens'

/** Everything the UI shows about one sale, read from the chain. */
export interface SaleState {
  e3Id: bigint
  creator: `0x${string}`
  title: string
  /** The price of each step, one per step the creator chose (2 to 16). A bid is below `prices.length`. */
  prices: PriceList
  saleToken: TokenInfo
  paymentToken: TokenInfo
  /** Sale-token base units on offer. */
  supply: bigint
  /** Payment-token base units that every bid locks. */
  escrow: bigint
  stage: E3Stage
  failureReason: FailureReason | null
  /** Unix seconds: bids are accepted from `inputWindow[0]` to `inputWindow[1]`. */
  inputWindow: readonly [bigint, bigint]
  /** The decrypted output, once the committee has published it. */
  plaintextOutput: `0x${string}` | null
  /** The bidder gate contract, or the zero address when anyone may bid. */
  gate: `0x${string}`
  /** Addresses that have bid at least once. */
  bidderCount: number
}

/** Where a sale is, in the order it passes through. `failed` can happen at any point. */
export type SalePhase = 'awaiting-key' | 'bidding' | 'computing' | 'decrypting' | 'complete' | 'failed'

export const PHASE_ORDER = ['awaiting-key', 'bidding', 'computing', 'decrypting', 'complete'] as const satisfies readonly SalePhase[]

export const PHASE_LABELS: Record<SalePhase, string> = {
  'awaiting-key': 'Waiting for committee key',
  bidding: 'Bidding open',
  computing: 'Computing',
  decrypting: 'Decrypting',
  complete: 'Sale cleared',
  failed: 'Failed',
}

/** The bytes the committee publishes are `0x` until the decryption is on chain. */
export function isPublished(plaintextOutput: string | undefined | null): plaintextOutput is `0x${string}` {
  return plaintextOutput !== undefined && plaintextOutput !== null && plaintextOutput.length > 2
}

/** `now` is chain time in unix seconds. */
export function phaseOf(sale: SaleState, now: bigint): SalePhase {
  if (sale.stage === E3Stage.Failed) return 'failed'
  if (sale.stage === E3Stage.Complete || isPublished(sale.plaintextOutput)) return 'complete'
  if (sale.stage === E3Stage.CiphertextReady) return 'decrypting'
  if (sale.stage === E3Stage.KeyPublished) return now <= sale.inputWindow[1] ? 'bidding' : 'computing'
  return 'awaiting-key'
}

/** "1h 05m", "4m 10s" or "0s" for a span in seconds. */
export function formatDuration(seconds: bigint): string {
  const total = Number(seconds > 0n ? seconds : 0n)
  const hours = Math.floor(total / 3600)
  const minutes = Math.floor((total % 3600) / 60)
  const rest = total % 60
  if (hours > 0) return `${hours}h ${String(minutes).padStart(2, '0')}m`
  if (minutes > 0) return `${minutes}m ${String(rest).padStart(2, '0')}s`
  return `${rest}s`
}

/** Sale ids found so far, and the block they are complete up to: later scans resume from there. */
const known = { ids: new Set<bigint>(), scannedTo: null as bigint | null }

/** The ids of every sale, newest first, from the `SaleCreated` events of the program. */
export async function listSaleIds(): Promise<bigint[]> {
  const { e3Program } = getContractAddresses()
  const from = known.scannedTo === null ? undefined : known.scannedTo + 1n
  const { logs, head } = await scanLogs(
    (range) =>
      publicClient.getContractEvents({
        address: e3Program,
        abi: SealedCcaProgram__factory.abi,
        eventName: 'SaleCreated',
        strict: true,
        ...range,
      }),
    from,
  )
  for (const { args } of logs) known.ids.add(args.e3Id)
  known.scannedTo = head
  return [...known.ids].sort((a, b) => (a < b ? 1 : a > b ? -1 : 0))
}

/** The state of one sale, or `null` if the program has no sale under `e3Id`. */
export async function loadSale(e3Id: bigint): Promise<SaleState | null> {
  const { e3Program } = getContractAddresses()
  const sdk = getReadSdk()
  const read = { address: e3Program, abi: SealedCcaProgram__factory.abi } as const
  const [config, prices, bidders] = await Promise.all([
    publicClient.readContract({ ...read, functionName: 'sale', args: [e3Id] }),
    publicClient.readContract({ ...read, functionName: 'salePrices', args: [e3Id] }),
    publicClient.readContract({ ...read, functionName: 'bidderCount', args: [e3Id] }),
  ])
  const [revealMode, levels, creator, title, saleTokenAddress, paymentTokenAddress, supply, escrow, gate] = config
  if (creator === zeroAddress) return null
  if (revealMode !== 0) throw new Error(`Sale ${e3Id} has the reveal mode ${revealMode}, which this app cannot show`)

  const [e3, stage, saleToken, paymentToken] = await Promise.all([
    sdk.getE3(e3Id),
    sdk.getE3Stage(e3Id),
    readTokenInfo(saleTokenAddress),
    readTokenInfo(paymentTokenAddress),
  ])
  const failureReason = stage === E3Stage.Failed ? await sdk.getFailureReason(e3Id) : null
  return {
    e3Id,
    creator,
    title,
    prices: readPriceList(levels, prices),
    saleToken,
    paymentToken,
    supply,
    escrow,
    stage,
    failureReason,
    inputWindow: e3.inputWindow,
    plaintextOutput: isPublished(e3.plaintextOutput) ? e3.plaintextOutput : null,
    gate,
    bidderCount: Number(bidders),
  }
}

/** A unix timestamp (seconds) as a local date and time. */
export function formatDateTime(seconds: bigint): string {
  return new Date(Number(seconds) * 1000).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

/** How long the bidding window has left, as the cards and the detail page show it. */
export function timeLeftLabel(sale: SaleState, phase: SalePhase, now: bigint): string {
  if (phase === 'awaiting-key' || phase === 'bidding') {
    return now < sale.inputWindow[1] ? `${formatDuration(sale.inputWindow[1] - now)} left` : 'Window ended'
  }
  return 'Bidding closed'
}

/** The price of step `level`, in whole payment tokens per whole sale token, without the symbol. */
export function formatStepPrice(sale: SaleState, level: number): string {
  return formatAmount(sale.prices[level], sale.paymentToken.decimals)
}

/** A price in payment-token base units (the clearing price may lie between two steps), in whole payment tokens. */
export function formatPriceValue(sale: SaleState, price: bigint): string {
  return formatAmount(price, sale.paymentToken.decimals, 6)
}

/** `amount` sale-token base units with the symbol. */
export function formatSaleTokens(sale: SaleState, amount: bigint): string {
  return `${formatAmount(amount, sale.saleToken.decimals)} ${sale.saleToken.symbol}`
}

/** `amount` payment-token base units with the symbol. */
export function formatPayment(sale: SaleState, amount: bigint): string {
  return `${formatAmount(amount, sale.paymentToken.decimals)} ${sale.paymentToken.symbol}`
}
