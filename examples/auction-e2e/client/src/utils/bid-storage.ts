// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { loadState, saveState } from './persistence'

/**
 * One bid of this browser that the chain accepted. The level never leaves the browser unencrypted, so
 * this record is the only place the bidder can read it again, for "your bid" and the result page.
 */
export interface StoredVersion {
  /** The bid version the contract gave it: 1 for the first bid, then one more for each update. */
  version: number
  /** The price step that was bid. */
  level: number
  txHash: `0x${string}`
}

export interface BidKey {
  chainId: number
  program: `0x${string}`
  e3Id: bigint
  account: `0x${string}`
}

const storageKey = ({ chainId, program, e3Id, account }: BidKey) =>
  `bids:${chainId}:${program.toLowerCase()}:${e3Id}:${account.toLowerCase()}`

/** The versions this browser submitted for `key`, ascending. */
export const loadVersions = (key: BidKey): StoredVersion[] => loadState<StoredVersion[]>(storageKey(key)) ?? []

/** Add an accepted bid to the list. A version that is already there is replaced. */
export function saveVersion(key: BidKey, entry: StoredVersion): void {
  const kept = loadVersions(key).filter(({ version }) => version !== entry.version)
  saveState(
    storageKey(key),
    [...kept, entry].sort((a, b) => a.version - b.version),
  )
}
