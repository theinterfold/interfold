// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { loadState, saveState } from './persistence'

/**
 * The offer of this browser that the chain accepted. The price step never leaves the browser
 * unencrypted, so this record is the only place the party can read its own price again.
 */
export interface StoredOffer {
  /** The price step that was offered (`s` of the seller, `b` of the buyer). */
  step: number
  txHash: `0x${string}`
}

export interface OfferKey {
  chainId: number
  program: `0x${string}`
  e3Id: bigint
  account: `0x${string}`
}

const storageKey = ({ chainId, program, e3Id, account }: OfferKey) =>
  `offer:${chainId}:${program.toLowerCase()}:${e3Id}:${account.toLowerCase()}`

/** The offer this browser submitted for `key`, or `null`. */
export const loadOffer = (key: OfferKey): StoredOffer | null => loadState<StoredOffer>(storageKey(key))

export const saveOffer = (key: OfferKey, offer: StoredOffer): void => saveState(storageKey(key), offer)
