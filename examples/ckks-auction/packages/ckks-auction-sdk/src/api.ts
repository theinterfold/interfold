// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Typed client for the coordination server (`examples/ckks-auction/server`).

import type { Address, Hex } from 'viem'

import type { BalanceEntry, BalanceProof, RoundDetail, RoundSummary } from './types'

export class AuctionApi {
  constructor(readonly baseUrl: string) {}

  private async get<T>(path: string): Promise<T> {
    const res = await fetch(`${this.baseUrl}${path}`)
    if (!res.ok) throw new Error(`${path}: ${res.status} ${await res.text()}`)
    return (await res.json()) as T
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    })
    if (!res.ok) throw new Error(`${path}: ${res.status} ${await res.text()}`)
    return (await res.json()) as T
  }

  status = () => this.get<{ chainId: number; block: number; programAddress: Address; interfoldAddress: Address; bidCap: number }>('/status')
  rounds = () => this.get<RoundSummary[]>('/rounds')
  round = (e3Id: string) => this.get<RoundDetail>(`/rounds/${e3Id}`)
  balanceProof = (e3Id: string, address: Address) => this.get<BalanceProof>(`/rounds/${e3Id}/balance-proof/${address}`)
  publicKey = async (e3Id: string): Promise<Uint8Array> => {
    const { publicKeyHex } = await this.get<{ publicKeyHex: Hex }>(`/rounds/${e3Id}/public-key`)
    const hex = publicKeyHex.slice(2)
    const out = new Uint8Array(hex.length / 2)
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16)
    return out
  }
  /** Admin: request a new E3 with a balance snapshot (server signs with its key and sets the root). */
  createRound = (snapshot: BalanceEntry[], durationSecs?: number) =>
    this.post<{ e3Id: string }>('/rounds/request', { snapshot, durationSecs })
  /** Admin: run winner-mode evaluation + publish the ciphertext output. */
  evaluate = (e3Id: string) => this.post<{ ok: boolean }>(`/rounds/${e3Id}/evaluate`, {})
}
