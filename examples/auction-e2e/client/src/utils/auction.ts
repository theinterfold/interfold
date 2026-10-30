// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { type Address, zeroAddress } from 'viem'
import { E3Stage, FailureReason } from '@interfold/sdk'
import { AuctionProgram__factory } from '@contract-types/factories/contracts/AuctionProgram__factory'
import { type AuctionType, isAuctionType, type PriceList, readPriceList } from '@interfold/auction-core'
import { hasProviders } from './designs'
import { getContractAddresses } from './env-config'
import { scanLogs } from './logs'
import { getReadSdk, publicClient } from './chain'
import { shortId } from './format'

/** A mask provider of a mask-provider auction and whether its mask is on chain. */
export interface MaskProviderState {
  address: Address
  submitted: boolean
}

/** Everything the UI shows about one auction, read from the chain. */
export interface AuctionState {
  e3Id: bigint
  auctionType: AuctionType
  creator: `0x${string}`
  title: string
  /** The price of each step, one per step the creator chose (2 to 16): a bid of step `l` costs `prices[l]`. A bid is below `prices.length`. */
  prices: PriceList
  stage: E3Stage
  failureReason: FailureReason | null
  /** Unix seconds: bids are accepted from `inputWindow[0]` to `inputWindow[1]`. */
  inputWindow: readonly [bigint, bigint]
  /** Unix seconds of the block that requested the E3. The committee key request starts here. */
  requestedAt: bigint
  /** The decrypted result, once the committee has published it. */
  plaintextOutput: `0x${string}` | null
  /** The bidder gate contract, or the zero address when anyone may bid. */
  gate: `0x${string}`
  /** Addresses that have bid at least once. They take a place of `MAX_BIDDERS`. */
  bidderCount: number
  /** The mask providers the creator named, in that order. Empty for the types that have none. */
  providers: readonly MaskProviderState[]
}

/** Where an auction is, in the order it passes through. `failed` can happen at any point. */
export type AuctionPhase = 'awaiting-key' | 'bidding' | 'computing' | 'decrypting' | 'complete' | 'failed'

export const PHASE_ORDER = ['awaiting-key', 'bidding', 'computing', 'decrypting', 'complete'] as const satisfies readonly AuctionPhase[]

export const PHASE_LABELS: Record<AuctionPhase, string> = {
  'awaiting-key': 'Waiting for committee key',
  bidding: 'Bidding open',
  computing: 'Computing',
  decrypting: 'Decrypting',
  complete: 'Result ready',
  failed: 'Failed',
}

/** The name of each step of the progress list: a noun, so that it reads the same before, during and after the step. */
export const STEP_TITLES: Record<(typeof PHASE_ORDER)[number], string> = {
  'awaiting-key': 'Committee key',
  bidding: 'Bidding',
  computing: 'Computation',
  decrypting: 'Decryption',
  complete: 'Result',
}

/** Why an auction failed, in words for the reader. Every reason has a line. */
export const FAILURE_TEXT: Record<FailureReason, string> = {
  [FailureReason.None]: 'No reason was recorded.',
  [FailureReason.CommitteeFormationTimeout]: 'The committee did not form in time.',
  [FailureReason.InsufficientCommitteeMembers]: 'Too few ciphernodes joined the committee.',
  [FailureReason.DKGTimeout]: 'The committee did not finish the key in time.',
  [FailureReason.DKGInvalidShares]: 'The committee produced invalid key shares.',
  [FailureReason.NoInputsReceived]: 'No bid arrived before the window closed.',
  [FailureReason.ComputeTimeout]: 'The computation did not finish in time.',
  [FailureReason.ComputeProviderExpired]: 'The program did not respond in time.',
  [FailureReason.ComputeProviderFailed]: 'The program failed to compute the result.',
  [FailureReason.RequesterCancelled]: 'The creator cancelled the auction.',
  [FailureReason.DecryptionTimeout]: 'The committee did not decrypt the result in time.',
  [FailureReason.DecryptionInvalidShares]: 'The committee produced invalid decryption shares.',
  [FailureReason.VerificationFailed]: 'The result did not pass verification.',
}

/** The bytes the committee publishes are `0x` until the decryption is on chain. */
export function isPublished(plaintextOutput: string | undefined | null): plaintextOutput is `0x${string}` {
  return plaintextOutput !== undefined && plaintextOutput !== null && plaintextOutput.length > 2
}

/** `now` is chain time in unix seconds. */
export function phaseOf(auction: AuctionState, now: bigint): AuctionPhase {
  if (auction.stage === E3Stage.Failed) return 'failed'
  if (auction.stage === E3Stage.Complete || isPublished(auction.plaintextOutput)) return 'complete'
  if (auction.stage === E3Stage.CiphertextReady) return 'decrypting'
  if (auction.stage === E3Stage.KeyPublished) return now <= auction.inputWindow[1] ? 'bidding' : 'computing'
  return 'awaiting-key'
}

/** How many of the mask providers of the auction have sent their mask. */
export function maskCount(auction: AuctionState): number {
  return auction.providers.filter((provider) => provider.submitted).length
}

/** Whether every mask is on chain. An auction without providers needs none. */
export function masksComplete(auction: AuctionState): boolean {
  return auction.providers.every((provider) => provider.submitted)
}

async function loadProviders(e3Id: bigint): Promise<MaskProviderState[]> {
  const { e3Program } = getContractAddresses()
  const read = { address: e3Program, abi: AuctionProgram__factory.abi } as const
  const addresses = await publicClient.readContract({ ...read, functionName: 'auctionProviders', args: [e3Id] })
  return Promise.all(
    addresses.map(async (address) => ({
      address,
      submitted: await publicClient.readContract({ ...read, functionName: 'maskSubmitted', args: [e3Id, address] }),
    })),
  )
}

/** Whole numbers with digit grouping: a price is a `uint256` that can exceed 2^53. */
export function formatPrice(level: number, prices: PriceList): string {
  return prices[level].toLocaleString('en-US')
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

/** Auction ids found so far, and the block they are complete up to: later scans resume from there. */
const known = { ids: new Set<bigint>(), scannedTo: null as bigint | null }

/** The ids of every auction, newest first, from the `AuctionCreated` events of the program. */
export async function listAuctionIds(): Promise<bigint[]> {
  const { e3Program } = getContractAddresses()
  const from = known.scannedTo === null ? undefined : known.scannedTo + 1n
  const { logs, head } = await scanLogs(
    (range) =>
      publicClient.getContractEvents({
        address: e3Program,
        abi: AuctionProgram__factory.abi,
        eventName: 'AuctionCreated',
        strict: true,
        ...range,
      }),
    from,
  )
  for (const { args } of logs) known.ids.add(args.e3Id)
  known.scannedTo = head
  return [...known.ids].sort((a, b) => (a < b ? 1 : a > b ? -1 : 0))
}

/** The state of one auction, or `null` if the program has no auction under `e3Id`. */
export async function loadAuction(e3Id: bigint): Promise<AuctionState | null> {
  const { e3Program } = getContractAddresses()
  const sdk = getReadSdk()
  const read = { address: e3Program, abi: AuctionProgram__factory.abi } as const
  const [config, prices, bidders] = await Promise.all([
    publicClient.readContract({ ...read, functionName: 'auctions', args: [e3Id] }),
    publicClient.readContract({ ...read, functionName: 'auctionPrices', args: [e3Id] }),
    publicClient.readContract({ ...read, functionName: 'bidderCount', args: [e3Id] }),
  ])
  const [auctionType, levels, creator, title, gate] = config
  if (creator === zeroAddress) return null
  if (!isAuctionType(auctionType)) throw new Error(`Auction ${shortId(e3Id)} has the unknown type ${auctionType}`)

  const [e3, stage, providers] = await Promise.all([
    sdk.getE3(e3Id),
    sdk.getE3Stage(e3Id),
    hasProviders(auctionType) ? loadProviders(e3Id) : Promise.resolve([]),
  ])
  const failureReason = stage === E3Stage.Failed ? await sdk.getFailureReason(e3Id) : null
  return {
    e3Id,
    auctionType,
    creator,
    title,
    prices: readPriceList(levels, prices),
    stage,
    failureReason,
    inputWindow: e3.inputWindow,
    requestedAt: e3.requestBlock,
    plaintextOutput: isPublished(e3.plaintextOutput) ? e3.plaintextOutput : null,
    gate,
    bidderCount: Number(bidders),
    providers,
  }
}

/** A unix timestamp (seconds) as a local date and time. */
export function formatDateTime(seconds: bigint): string {
  return new Date(Number(seconds) * 1000).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

/** How long the bidding window has left, as the cards and the detail page show it. */
export function timeLeftLabel(auction: AuctionState, phase: AuctionPhase, now: bigint): string {
  if (phase === 'awaiting-key' || phase === 'bidding') {
    return now < auction.inputWindow[1] ? `${formatDuration(auction.inputWindow[1] - now)} left` : 'Window ended'
  }
  return 'Bidding closed'
}
