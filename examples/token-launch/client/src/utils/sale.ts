// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { zeroAddress } from 'viem'
import { E3Stage, FailureReason } from '@interfold/sdk'
import { type PriceList, readPriceList, readTierList } from '@interfold/token-launch'
import { TokenLaunchProgram__factory } from '@contract-types/factories/contracts/TokenLaunchProgram__factory'
import { getContractAddresses } from './env-config'
import { scanLogs } from './logs'
import { getReadSdk, publicClient } from './chain'
import { Phase, formatDuration } from './phase'
import { type TokenInfo, formatAmount, readTokenInfo } from './tokens'

export type ClearingKind = 'undersubscribed' | 'capped' | 'uncapped'

/** The `kind` codes of the contract: 0, 1, 2. */
const KINDS: readonly ClearingKind[] = ['undersubscribed', 'capped', 'uncapped']

/** The clearing of a sale as the contract computed it. Amounts are in the units named on each field. */
export interface ClearingInfo {
  kind: ClearingKind
  /** `k` of the claim proof: `s` for a capped sale, `l` for an uncapped one, 0 when undersubscribed. */
  step: number
  /** The uniform price in payment-token base units per whole sale token. */
  pStar: bigint
  /** Sale-token base units sold in all. */
  sold: bigint
  /** Sale-token base units left for the bids at the clearing step, in bid order (capped sales). */
  remaining: bigint
  /** Unix seconds: a claim at the clearing step of a capped sale registers until then; `payMarginal` works after it. */
  marginalDeadline: bigint
  /** Unix seconds: the last second at which `claim` works. After it the creator can sweep. */
  claimDeadline: bigint
  /** Bit `i` is set when bid `i` was counted. */
  countedMask: bigint
  /** The root of the claim tree, final after the clearing. */
  root: bigint
}

/** The probe search of round 1, as `probeInfo` returns it. */
export interface ProbeInfo {
  lo: number
  hi: number
  probeMask1: number
  probeMask2: number
  /** Budget-unit sums at the levels of `probeMask1`. */
  sums1: readonly bigint[]
}

/** The reason that the program stopped a sale, from the `SaleAborted` event: the `AbortReason` enum. */
export const ABORT_TEXT: Record<number, string> = {
  1: 'The creator did not request round 2 in time.',
  2: 'The output of round 1 was not valid.',
  3: 'The output of round 2 was not valid.',
  4: 'The two rounds did not count the same bids.',
}

/** Everything the UI shows about one sale, read from the chain. `saleId` is the E3 id of round 1. */
export interface SaleState {
  saleId: bigint
  /** The E3 id of round 2, or `null` before the creator links it. */
  roundTwoId: bigint | null
  creator: `0x${string}`
  title: string
  levels: number
  /** The price of each step, `levels` values in payment-token base units per whole sale token. */
  prices: PriceList
  saleToken: TokenInfo
  paymentToken: TokenInfo
  /** Sale-token base units on offer. */
  supply: bigint
  /** Payment-token base units in one budget unit. */
  budgetUnit: bigint
  /** The escrow tiers in budget units, ascending. */
  tiers: readonly number[]
  phase: Phase
  /** Why the sale stopped: the E3 failure of a failed sale or the program's abort reason. */
  stopReason: string | null
  /** Unix seconds: bids are accepted from `inputWindow[0]` to `inputWindow[1]`. */
  inputWindow: readonly [bigint, bigint]
  /** Both committee keys exist. */
  keysReady: boolean
  bidCount: number
  probes: ProbeInfo | null
  clearing: ClearingInfo | null
}

const FAILURE_TEXT: Partial<Record<FailureReason, string>> = {
  [FailureReason.CommitteeFormationTimeout]: 'The committee did not form in time.',
  [FailureReason.InsufficientCommitteeMembers]: 'Too few ciphernodes joined the committee.',
  [FailureReason.DKGTimeout]: 'The committee did not finish its key in time.',
  [FailureReason.DKGInvalidShares]: 'The committee key generation produced invalid shares.',
  [FailureReason.NoInputsReceived]: 'No bids were received before the window closed.',
  [FailureReason.ComputeTimeout]: 'The computation did not finish in time.',
  [FailureReason.ComputeProviderExpired]: 'The compute provider expired.',
  [FailureReason.ComputeProviderFailed]: 'The compute provider failed.',
  [FailureReason.RequesterCancelled]: 'The creator cancelled the sale.',
  [FailureReason.DecryptionTimeout]: 'The committee did not decrypt the result in time.',
  [FailureReason.DecryptionInvalidShares]: 'The decryption produced invalid shares.',
  [FailureReason.VerificationFailed]: 'The result failed verification.',
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
        abi: TokenLaunchProgram__factory.abi,
        eventName: 'SaleCreated',
        strict: true,
        ...range,
      }),
    from,
  )
  for (const { args } of logs) known.ids.add(args.saleId)
  known.scannedTo = head
  return [...known.ids].sort((a, b) => (a < b ? 1 : a > b ? -1 : 0))
}

/** The `SaleAborted` reason of a sale, as text. */
async function readAbortReason(saleId: bigint): Promise<string> {
  const { e3Program } = getContractAddresses()
  const { logs } = await scanLogs((range) =>
    publicClient.getContractEvents({
      address: e3Program,
      abi: TokenLaunchProgram__factory.abi,
      eventName: 'SaleAborted',
      args: { saleId },
      strict: true,
      ...range,
    }),
  )
  const reason = logs.at(-1)?.args.reason
  return (reason !== undefined && ABORT_TEXT[reason]) || 'The program stopped the sale.'
}

/** The state of one sale, or `null` if the program has no sale under `saleId`. */
export async function loadSale(saleId: bigint): Promise<SaleState | null> {
  const { e3Program } = getContractAddresses()
  const sdk = getReadSdk()
  const read = { address: e3Program, abi: TokenLaunchProgram__factory.abi } as const
  const [info, roundTwo, prices, tiers, bidCount, phase, probes, clearing] = await Promise.all([
    publicClient.readContract({ ...read, functionName: 'getSale', args: [saleId] }),
    publicClient.readContract({ ...read, functionName: 'roundTwo', args: [saleId] }),
    publicClient.readContract({ ...read, functionName: 'salePrices', args: [saleId] }),
    publicClient.readContract({ ...read, functionName: 'saleTiers', args: [saleId] }),
    publicClient.readContract({ ...read, functionName: 'bidCount', args: [saleId] }),
    publicClient.readContract({ ...read, functionName: 'phase', args: [saleId] }),
    publicClient.readContract({ ...read, functionName: 'probeInfo', args: [saleId] }),
    publicClient.readContract({ ...read, functionName: 'clearing', args: [saleId] }),
  ])
  if (info.creator === zeroAddress) return null

  // E3 id 0 is never a round 2.
  const roundTwoId = roundTwo === 0n ? null : roundTwo
  const [e3, stage1, stage2, saleToken, paymentToken] = await Promise.all([
    sdk.getE3(saleId),
    sdk.getE3Stage(saleId),
    roundTwoId === null ? Promise.resolve(null) : sdk.getE3Stage(roundTwoId),
    readTokenInfo(info.saleToken),
    readTokenInfo(info.paymentToken),
  ])

  let stopReason: string | null = null
  if (phase === Phase.Failed) {
    const failed = stage1 === E3Stage.Failed ? saleId : roundTwoId
    const reason = failed === null ? FailureReason.None : await sdk.getFailureReason(failed)
    stopReason = FAILURE_TEXT[reason] ?? `An E3 run failed (${FailureReason[reason]}).`
  } else if (phase === Phase.Aborted) {
    stopReason = await readAbortReason(saleId)
  }

  const [lo, hi, probeMask1, probeMask2, sums1] = probes
  return {
    saleId,
    roundTwoId,
    creator: info.creator,
    title: info.title,
    levels: info.levels,
    prices: readPriceList(info.levels, prices),
    saleToken,
    paymentToken,
    supply: info.supply,
    budgetUnit: info.budgetUnit,
    tiers: readTierList(tiers),
    phase: phase as Phase,
    stopReason,
    inputWindow: e3.inputWindow,
    keysReady: stage1 >= E3Stage.KeyPublished && stage2 !== null && stage2 >= E3Stage.KeyPublished,
    bidCount: Number(bidCount),
    probes: phase >= Phase.Round2 && phase !== Phase.Failed ? { lo, hi, probeMask1, probeMask2, sums1 } : null,
    clearing: clearing.cleared
      ? {
          kind: KINDS[clearing.kind],
          step: clearing.step,
          pStar: clearing.pStar,
          sold: clearing.sold,
          remaining: clearing.remaining,
          marginalDeadline: BigInt(clearing.marginalDeadline),
          claimDeadline: BigInt(clearing.claimDeadline),
          countedMask: clearing.countedMask,
          root: clearing.root,
        }
      : null,
  }
}

/**
 * The budget sums that the committee revealed, in budget units, indexed by step: `null` where a step
 * was not probed. Before the clearing these are the round 1 sums; the `SaleCleared` event adds round 2.
 */
export async function readRevealedSums(sale: SaleState): Promise<(bigint | null)[]> {
  const sums: (bigint | null)[] = Array.from({ length: sale.levels }, () => null)
  if (sale.probes) {
    for (let level = 0; level < sale.levels; level++) {
      if ((sale.probes.probeMask1 >> level) & 1) sums[level] = sale.probes.sums1[level]
    }
  }
  if (sale.clearing) {
    const { e3Program } = getContractAddresses()
    const { logs } = await scanLogs((range) =>
      publicClient.getContractEvents({
        address: e3Program,
        abi: TokenLaunchProgram__factory.abi,
        eventName: 'SaleCleared',
        args: { saleId: sale.saleId },
        strict: true,
        ...range,
      }),
    )
    const event = logs.at(-1)
    if (event) {
      for (let level = 0; level < sale.levels; level++) {
        if ((event.args.knownMask >> level) & 1) sums[level] = event.args.sums[level]
      }
    }
  }
  return sums
}

/** A unix timestamp (seconds) as a local date and time. */
export function formatDateTime(seconds: bigint): string {
  return new Date(Number(seconds) * 1000).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

/** How long the bidding window has left, as the cards and the detail page show it. */
export function timeLeftLabel(sale: SaleState, now: bigint): string {
  if (sale.phase === Phase.Bidding) {
    if (now < sale.inputWindow[0]) return `Opens in ${formatDuration(sale.inputWindow[0] - now)}`
    return now < sale.inputWindow[1] ? `${formatDuration(sale.inputWindow[1] - now)} left` : 'Window ended'
  }
  return 'Bidding closed'
}

/** The price of step `step`, in whole payment tokens per whole sale token, without the symbol. */
export function formatStepPrice(sale: SaleState, step: number): string {
  return formatAmount(sale.prices[step], sale.paymentToken.decimals)
}

/** A price in payment-token base units, in whole payment tokens. */
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

/** `units` budget units as a payment amount with the symbol. */
export function formatBudget(sale: SaleState, units: number | bigint): string {
  return formatPayment(sale, BigInt(units) * sale.budgetUnit)
}
