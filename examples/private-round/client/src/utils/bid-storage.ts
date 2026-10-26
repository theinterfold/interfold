// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { loadState, saveState } from './persistence'

/**
 * One bid of this browser that the chain accepted. The step and the salt never leave the browser
 * unencrypted, so this record is the only place the bidder can read them again: for "your bid" and
 * for the claim proof, which proves the commitment opens to the step.
 */
export interface StoredVersion {
  /** The bid version the contract gave it: 1 for the first bid, then one more for each update. */
  version: number
  /** The price step that was bid (`b`). */
  level: number
  /** The salt of the bid commitment, as a hex field element. */
  salt: `0x${string}`
  /** The commitment of this version, as the contract stores it. */
  bidCommitment: `0x${string}`
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
