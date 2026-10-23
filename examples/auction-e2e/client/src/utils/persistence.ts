// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { E3_PROGRAM_ADDRESS, INTERFOLD_ADDRESS, REGISTRY_ADDRESS } from './env-config'
import { publicClient } from './chain'

/**
 * State from another deployment must never be reused. A fresh anvil redeploys the same addresses, so
 * the fingerprint holds the hash of the chain's genesis block too. Until `initPersistence` has read
 * it there is no fingerprint, and nothing is loaded or saved.
 */
let fingerprint: string | null = null

/** Read the genesis block hash and enable the storage. Call once before the app renders. */
export async function initPersistence(): Promise<void> {
  try {
    const genesis = await publicClient.getBlock({ blockNumber: 0n })
    fingerprint = [genesis.hash, INTERFOLD_ADDRESS, E3_PROGRAM_ADDRESS, REGISTRY_ADDRESS].join('|')
  } catch (err) {
    console.warn('Could not read the genesis block; the browser will not store bids:', err)
  }
}

const PREFIX = 'auction-e2e:'

const BIGINT_TAG = '__bigint__'

const replacer = (_key: string, value: unknown): unknown => (typeof value === 'bigint' ? { [BIGINT_TAG]: value.toString() } : value)

const reviver = (_key: string, value: unknown): unknown => {
  if (value !== null && typeof value === 'object' && BIGINT_TAG in value && typeof value[BIGINT_TAG] === 'string') {
    return BigInt(value[BIGINT_TAG])
  }
  return value
}

/** Best-effort: a full or disabled localStorage must never break the app. */
export function saveState<T>(key: string, value: T): void {
  if (fingerprint === null) return
  try {
    localStorage.setItem(PREFIX + key, JSON.stringify({ fingerprint, value }, replacer))
  } catch {
    // Ignore.
  }
}

export function loadState<T>(key: string): T | null {
  if (fingerprint === null) return null
  try {
    const raw = localStorage.getItem(PREFIX + key)
    if (!raw) return null
    const stored: unknown = JSON.parse(raw, reviver)
    if (!stored || typeof stored !== 'object' || !('fingerprint' in stored) || !('value' in stored)) return null
    if (stored.fingerprint !== fingerprint) {
      clearState(key)
      return null
    }
    // Unchecked: this module wrote the value under the same key and deployment fingerprint.
    const value = stored.value as T
    return value
  } catch {
    return null
  }
}

export function clearState(key: string): void {
  try {
    localStorage.removeItem(PREFIX + key)
  } catch {
    // Ignore.
  }
}
