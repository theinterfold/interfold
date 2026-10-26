// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { loadState, saveState } from './persistence'

/**
 * A claim that this browser sent. It keeps the nullifier (the public name of the claim) with the
 * fresh recipient and the amounts, so the result stays visible after a reload. The private key of a
 * generated recipient is here too: without it the funds are lost, so it must outlive the tab. The
 * record is saved before the claim is sent.
 */
export interface ClaimRecord {
  saleId: bigint
  nullifier: `0x${string}`
  recipient: `0x${string}`
  /** The private key of a recipient that the app generated; `null` when the user typed an address. */
  recipientKey: `0x${string}` | null
  /** What the contract previewed for the claim. The `Claimed` event is the final value. */
  tokens: bigint
  paid: bigint
  refund: bigint
  /** `null` until the relayer answers. */
  txHash: `0x${string}` | null
}

const storageKey = (chainId: number, program: `0x${string}`, saleId: bigint) => `claims:${chainId}:${program.toLowerCase()}:${saleId}`

export const loadClaims = (chainId: number, program: `0x${string}`, saleId: bigint): ClaimRecord[] =>
  loadState<ClaimRecord[]>(storageKey(chainId, program, saleId)) ?? []

/** Add a record, or replace the one with the same nullifier. */
export function saveClaim(chainId: number, program: `0x${string}`, record: ClaimRecord): void {
  const kept = loadClaims(chainId, program, record.saleId).filter(({ nullifier }) => nullifier !== record.nullifier)
  saveState(storageKey(chainId, program, record.saleId), [...kept, record])
}
