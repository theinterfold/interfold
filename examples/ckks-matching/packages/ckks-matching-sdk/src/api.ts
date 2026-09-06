// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Typed client for the coordination server (`examples/ckks-matching/server`).

import type { Address, Hex } from 'viem'

import type { RoundDetail, RoundResults, RoundSummary, SlotResponse } from './types'

export interface ServerStatus {
  chainId: number
  block: number
  programAddress: Address
  interfoldAddress: Address
  paramSet: number
  k: number
  parties: number
  maskWidth: number
  maskBound: number
  entryBound: number
  openingLevel: number
  ceremonyKeys: string[]
  outputCount: number
  outputDecimals: number
}

export class MatchingApi {
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

  status = () => this.get<ServerStatus>('/status')
  rounds = () => this.get<RoundSummary[]>('/rounds')
  round = (e3Id: string) => this.get<RoundDetail>(`/rounds/${e3Id}`)
  /** The party's registered slot (0 = A / forward, 1 = B / reversed). */
  slot = (e3Id: string, address: Address) => this.get<SlotResponse>(`/rounds/${e3Id}/slot/${address}`)
  result = (e3Id: string) => this.get<RoundResults>(`/rounds/${e3Id}/result`)
  publicKey = async (e3Id: string): Promise<Uint8Array> => {
    const { publicKeyHex } = await this.get<{ publicKeyHex: Hex }>(`/rounds/${e3Id}/public-key`)
    const hex = publicKeyHex.slice(2)
    const out = new Uint8Array(hex.length / 2)
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16)
    return out
  }
  /** Admin: request a new E3 for two parties (server signs with its key and registers `[A, B]`). */
  createRound = (partyA: Address, partyB: Address, durationSecs?: number) =>
    this.post<{ e3Id: string }>('/rounds/request', { partyA, partyB, durationSecs })
  /** Admin: run the matching policy + publish the ciphertext output (needs both parties). */
  evaluate = (e3Id: string) => this.post<{ ok: boolean }>(`/rounds/${e3Id}/evaluate`, {})
}
