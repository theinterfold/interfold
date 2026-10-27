// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { zeroAddress } from 'viem'
import { E3Stage, FailureReason } from '@interfold/sdk'
import { Role, negotiationProgramAbi, priceAt } from '@interfold/negotiation'
import { getContractAddresses } from './env-config'
import { scanLogs } from './logs'
import { getReadSdk, publicClient } from './chain'

/** Everything the UI shows about one negotiation, read from the chain. */
export interface NegotiationState {
  e3Id: bigint
  creator: `0x${string}`
  seller: `0x${string}`
  buyer: `0x${string}`
  /** The levels of the price grid (2 to 16). A price step is below it. */
  levels: number
  /** The price of level 0, and the distance between two levels. */
  minPrice: bigint
  stepPrice: bigint
  /** The title without the unit label. */
  title: string
  /** The unit label of the prices, or an empty string. */
  unit: string
  stage: E3Stage
  failureReason: FailureReason | null
  /** Unix seconds: offers are accepted from `inputWindow[0]` to `inputWindow[1]`. */
  inputWindow: readonly [bigint, bigint]
  /** The decrypted output, once the committee has published it. */
  plaintextOutput: `0x${string}` | null
  /** Whether the seller and the buyer have each sent an offer. */
  offered: { seller: boolean; buyer: boolean }
  /** The result that `settle` stored. `step` and `price` are 0 when `matched` is false. */
  outcome: { settled: boolean; matched: boolean; step: number; price: bigint }
}

/**
 * The unit label is not on chain as a field. The create form appends it to the title as ` [unit]`, and this
 * module splits it again, so the contract keeps a single string.
 */
const UNIT_SUFFIX = /^(.*\S) \[([^[\]]{1,12})\]$/

export const joinTitle = (title: string, unit: string): string => (unit === '' ? title : `${title} [${unit}]`)

export function splitTitle(stored: string): { title: string; unit: string } {
  const match = UNIT_SUFFIX.exec(stored)
  return match ? { title: match[1], unit: match[2] } : { title: stored, unit: '' }
}

/** The role of `account` in the negotiation, or `null` if it is neither the seller nor the buyer. */
export function roleOf(negotiation: Pick<NegotiationState, 'seller' | 'buyer'>, account: string | undefined): Role | null {
  if (account === undefined) return null
  const lower = account.toLowerCase()
  if (lower === negotiation.seller.toLowerCase()) return Role.Seller
  if (lower === negotiation.buyer.toLowerCase()) return Role.Buyer
  return null
}

export const ROLE_NAMES: Record<Role, 'seller' | 'buyer'> = { [Role.Seller]: 'seller', [Role.Buyer]: 'buyer' }

/**
 * Where a negotiation is, in the order it passes through. `failed` can happen at any point. `incomplete`: the offer window
 * closed without an offer of each party, so the program has nothing to compare and the negotiation stops there.
 */
export type NegotiationPhase = 'awaiting-key' | 'offers' | 'computing' | 'decrypting' | 'settling' | 'settled' | 'incomplete' | 'failed'

/** The steps of the timeline. `settling` (decrypted, not yet settled) is the active `settled` step. */
export const PHASE_ORDER = ['awaiting-key', 'offers', 'computing', 'decrypting', 'settled'] as const satisfies readonly NegotiationPhase[]

export const PHASE_LABELS: Record<NegotiationPhase, string> = {
  'awaiting-key': 'Waiting for committee key',
  offers: 'Offers open',
  computing: 'Computing',
  decrypting: 'Decrypting',
  settling: 'Ready to settle',
  settled: 'Settled',
  incomplete: 'Offer missing',
  failed: 'Failed',
}

/** The bytes the committee publishes are `0x` until the decryption is on chain. */
export function isPublished(plaintextOutput: string | undefined | null): plaintextOutput is `0x${string}` {
  return plaintextOutput !== undefined && plaintextOutput !== null && plaintextOutput.length > 2
}

/** `now` is chain time in unix seconds. */
export function phaseOf(negotiation: NegotiationState, now: bigint): NegotiationPhase {
  if (negotiation.stage === E3Stage.Failed) return 'failed'
  if (negotiation.outcome.settled) return 'settled'
  if (negotiation.stage === E3Stage.Complete || isPublished(negotiation.plaintextOutput)) return 'settling'
  if (negotiation.stage === E3Stage.CiphertextReady) return 'decrypting'
  if (negotiation.stage === E3Stage.KeyPublished) {
    if (now <= negotiation.inputWindow[1]) return 'offers'
    return negotiation.offered.seller && negotiation.offered.buyer ? 'computing' : 'incomplete'
  }
  return 'awaiting-key'
}

/** The parties that sent no offer, as a sentence. */
export function missingOffersText(offered: NegotiationState['offered']): string {
  if (!offered.seller && !offered.buyer) return 'Neither the seller nor the buyer sent an offer.'
  return offered.seller ? 'The buyer sent no offer.' : 'The seller sent no offer.'
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

/** A unix timestamp (seconds) as a local date and time. */
export function formatDateTime(seconds: bigint): string {
  return new Date(Number(seconds) * 1000).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

/** How long the offer window has left, as the cards and the detail page show it. */
export function timeLeftLabel(negotiation: NegotiationState, phase: NegotiationPhase, now: bigint): string {
  if (phase === 'awaiting-key' || phase === 'offers') {
    return now < negotiation.inputWindow[1] ? `${formatDuration(negotiation.inputWindow[1] - now)} left` : 'Window ended'
  }
  return 'Offers closed'
}

/** A price as a number with its unit label. */
export function formatPrice(negotiation: Pick<NegotiationState, 'unit'>, price: bigint): string {
  const text = price.toLocaleString('en-US')
  return negotiation.unit === '' ? text : `${text} ${negotiation.unit}`
}

/** The price of the level `step`, with the unit label. */
export function formatLevel(negotiation: NegotiationState, step: number): string {
  return formatPrice(negotiation, priceAt(negotiation.minPrice, negotiation.stepPrice, step))
}

/** The ids found so far, and the block they are complete up to: later scans resume from there. */
const known = { ids: new Set<bigint>(), scannedTo: null as bigint | null }

/** The ids of every negotiation, newest first, from the `NegotiationCreated` events of the program. */
export async function listNegotiationIds(): Promise<bigint[]> {
  const { e3Program } = getContractAddresses()
  const from = known.scannedTo === null ? undefined : known.scannedTo + 1n
  const { logs, head } = await scanLogs(
    (range) =>
      publicClient.getContractEvents({
        address: e3Program,
        abi: negotiationProgramAbi,
        eventName: 'NegotiationCreated',
        strict: true,
        ...range,
      }),
    from,
  )
  for (const { args } of logs) known.ids.add(args.e3Id)
  known.scannedTo = head
  return [...known.ids].sort((a, b) => (a < b ? 1 : a > b ? -1 : 0))
}

/** The state of one negotiation, or `null` if the program has none under `e3Id`. */
export async function loadNegotiation(e3Id: bigint): Promise<NegotiationState | null> {
  const { e3Program } = getContractAddresses()
  const sdk = getReadSdk()
  const read = { address: e3Program, abi: negotiationProgramAbi } as const
  const [config, sellerOffered, buyerOffered, outcome] = await Promise.all([
    publicClient.readContract({ ...read, functionName: 'negotiation', args: [e3Id] }),
    publicClient.readContract({ ...read, functionName: 'offerSubmitted', args: [e3Id, Role.Seller] }),
    publicClient.readContract({ ...read, functionName: 'offerSubmitted', args: [e3Id, Role.Buyer] }),
    publicClient.readContract({ ...read, functionName: 'outcome', args: [e3Id] }),
  ])
  const [creator, seller, buyer, levels, minPrice, stepPrice, storedTitle] = config
  if (creator === zeroAddress) return null

  const [e3, stage] = await Promise.all([sdk.getE3(e3Id), sdk.getE3Stage(e3Id)])
  const failureReason = stage === E3Stage.Failed ? await sdk.getFailureReason(e3Id) : null
  const [settled, matched, step, price] = outcome
  return {
    e3Id,
    creator,
    seller,
    buyer,
    levels,
    minPrice,
    stepPrice,
    ...splitTitle(storedTitle),
    stage,
    failureReason,
    inputWindow: e3.inputWindow,
    plaintextOutput: isPublished(e3.plaintextOutput) ? e3.plaintextOutput : null,
    offered: { seller: sellerOffered, buyer: buyerOffered },
    outcome: { settled, matched, step, price },
  }
}
