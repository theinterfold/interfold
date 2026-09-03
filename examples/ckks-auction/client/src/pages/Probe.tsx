// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Browser proving benchmark (no chain, no server): encrypts a bid under a fixture ParamSet-2 public
// key and runs the complete three-leg pipeline in this tab. Used by `scripts/e2e.mjs --probe` to
// verify the Vite bundle (bb.js workers, WASM, circuits) and to measure per-leg proving times.

import { useState } from 'react'
import { encryptAndProveBid, BalanceTree } from '@ckks-auction/sdk'
import type { BidSubmission } from '@ckks-auction/sdk'

import { ensureCircuits } from '../api'

const FIXTURE = '0x976EA74026E726554dB657fA54763abd0C3a0aa9' as const

export const Probe = () => {
  const [log, setLog] = useState<string[]>([])
  const [result, setResult] = useState<BidSubmission | null>(null)
  const [error, setError] = useState<string | null>(null)
  const push = (m: string) => setLog((l) => [...l, m])

  const run = async (bid: number) => {
    setLog([])
    setError(null)
    setResult(null)
    try {
      const pkRes = await fetch('/fixtures/pubkey_ps2.bin')
      if (!pkRes.ok) throw new Error('fixture pk missing (client/public/fixtures/pubkey_ps2.bin)')
      const pk = new Uint8Array(await pkRes.arrayBuffer())
      await ensureCircuits()
      const tree = new BalanceTree([
        { address: FIXTURE, balance: '800' },
        { address: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8', balance: '300' },
      ])
      const proof = tree.proof(FIXTURE)
      const sub = await encryptAndProveBid(pk, bid, proof, FIXTURE, (s, ms) => push(`${Math.round(ms)} ms: ${JSON.stringify(s)}`))
      setResult(sub)
    } catch (e) {
      setError((e as Error).message)
    }
  }

  return (
    <>
      <h1>Browser proving probe</h1>
      <div className="row">
        <button data-testid="probe-ok" onClick={() => run(700)}>prove bid 700 (balance 800)</button>
        <button data-testid="probe-over" className="secondary" onClick={() => run(900)}>prove bid 900 (over balance → must fail)</button>
      </div>
      <pre data-testid="probe-log">{log.join('\n')}</pre>
      {error && <p className="badge bad" data-testid="probe-error">{error}</p>}
      {result && (
        <pre data-testid="probe-result">{JSON.stringify({ u: result.uCommitment, m: result.mCommitment, ct: (result.ciphertext.length - 2) / 2, timings: result.timings }, null, 1)}</pre>
      )}
    </>
  )
}
