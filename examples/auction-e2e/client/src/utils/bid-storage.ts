// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { type AuctionType, type Role, rolesFor } from '@shared/layout'
import type { BidSecret } from '@shared/prover'
import { loadState, saveState } from './persistence'

export interface StoredRole {
  /** `sent`: the transaction was handed to the wallet; it may or may not be mined yet. */
  status: 'pending' | 'sent' | 'done'
  txHash?: `0x${string}`
}

/**
 * What a bidder keeps private for one auction: the bid level and the salt of its commitment, plus
 * how far the submission got. The chain stays the source of truth for the roles (`submittedRoles`);
 * this record lets the bidder finish with the same bid and see "your bid" after a reload. It holds one
 * entry for each role of the auction type, so a type with three roles has no entry for the fourth.
 */
export interface StoredBid extends BidSecret {
  roles: Partial<Record<Role, StoredRole>>
}

export interface BidKey {
  chainId: number
  program: `0x${string}`
  e3Id: bigint
  account: `0x${string}`
}

const storageKey = ({ chainId, program, e3Id, account }: BidKey) =>
  `bid:${chainId}:${program.toLowerCase()}:${e3Id}:${account.toLowerCase()}`

export function emptyRoles(type: AuctionType): Partial<Record<Role, StoredRole>> {
  return Object.fromEntries(rolesFor(type).map((role) => [role, { status: 'pending' as const }]))
}

export const loadBid = (key: BidKey): StoredBid | null => loadState<StoredBid>(storageKey(key))

export const saveBid = (key: BidKey, bid: StoredBid): void => saveState(storageKey(key), bid)

/** Whether any ciphertext of this bid was sent: from then on the secret must never be replaced. */
export const hasSentRole = (bid: StoredBid): boolean => Object.values(bid.roles).some((stored) => stored.txHash !== undefined)

/**
 * Save a bid and read it back. `saveState` is best-effort, but a secret that was not stored would
 * leave a half-published bid that can never be finished, so the caller stops before sending anything.
 */
export function saveBidChecked(key: BidKey, bid: StoredBid): void {
  saveBid(key, bid)
  const back = loadBid(key)
  if (!back || back.salt !== bid.salt || back.bid !== bid.bid) {
    throw new Error(
      'This browser cannot store the bid secret (is localStorage disabled or full?). Nothing was sent. Fix the storage and try again.',
    )
  }
}
