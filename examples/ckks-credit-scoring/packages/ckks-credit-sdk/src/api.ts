// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Typed client for the coordination server (`examples/ckks-credit-scoring/server`).

import type { Address, Hex } from 'viem'

import type { ApplicantEntry, FeatureProof, Model, RoundDetail, RoundSummary } from './types'

export class CreditApi {
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

  status = () => this.get<{ chainId: number; block: number; programAddress: Address; interfoldAddress: Address; paramSet: number; maxApplicants: number }>('/status')
  rounds = () => this.get<RoundSummary[]>('/rounds')
  round = (e3Id: string) => this.get<RoundDetail>(`/rounds/${e3Id}`)
  featureProof = (e3Id: string, address: Address) => this.get<FeatureProof>(`/rounds/${e3Id}/feature-proof/${address}`)
  publicKey = async (e3Id: string): Promise<Uint8Array> => {
    const { publicKeyHex } = await this.get<{ publicKeyHex: Hex }>(`/rounds/${e3Id}/public-key`)
    const hex = publicKeyHex.slice(2)
    const out = new Uint8Array(hex.length / 2)
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16)
    return out
  }
  /** Admin: request a new E3 with an issuer snapshot + public model (server signs with its key and sets the root). */
  createRound = (snapshot: ApplicantEntry[], model: Model, durationSecs?: number) =>
    this.post<{ e3Id: string }>('/rounds/request', { snapshot, model, durationSecs })
  /** Admin: run the scoring policy + publish the ciphertext output. */
  evaluate = (e3Id: string) => this.post<{ ok: boolean }>(`/rounds/${e3Id}/evaluate`, {})
}
