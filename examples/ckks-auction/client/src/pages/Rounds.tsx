// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import type { BalanceEntry } from '@ckks-auction/sdk'

import { api } from '../api'
import { DEV_KEYS } from '../wallet'
import { privateKeyToAddress } from 'viem/accounts'

const DEFAULT_SNAPSHOT: BalanceEntry[] = DEV_KEYS.map((k, i) => ({
  address: privateKeyToAddress(k.key),
  balance: ['100', '500', '1000', '1000', '1000'][i],
}))

export const Rounds = () => {
  const qc = useQueryClient()
  const rounds = useQuery({ queryKey: ['rounds'], queryFn: () => api.rounds() })
  const [snapshot, setSnapshot] = useState(JSON.stringify(DEFAULT_SNAPSHOT, null, 2))
  const [duration, setDuration] = useState(300)
  const open = useMutation({
    mutationFn: async () => api.createRound(JSON.parse(snapshot) as BalanceEntry[], duration),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rounds'] }),
  })

  return (
    <>
      <h1>Rounds</h1>
      <div className="panel">
        <table>
          <thead>
            <tr>
              <th>E3</th>
              <th>Status</th>
              <th>Bids</th>
              <th>Window</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {(rounds.data ?? []).map((r) => (
              <tr key={r.e3Id} data-testid={`round-${r.e3Id}`}>
                <td className="mono">#{r.e3Id}</td>
                <td>
                  <span className={`badge ${r.status === 'finished' ? 'ok' : r.status === 'failed' ? 'bad' : 'info'}`}>{r.status}</span>
                </td>
                <td>{r.bidCount}</td>
                <td className="mono">
                  {new Date(r.inputWindow[0] * 1000).toLocaleTimeString()} → {new Date(r.inputWindow[1] * 1000).toLocaleTimeString()}
                </td>
                <td>
                  <Link to={`/rounds/${r.e3Id}`}>open</Link>
                </td>
              </tr>
            ))}
            {rounds.data?.length === 0 && (
              <tr>
                <td colSpan={5} className="muted">no rounds yet</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <h2>Open a round (admin)</h2>
      <div className="panel">
        <p className="muted">
          The server requests an E3 through <span className="mono">CkksAuctionE3Program</span> (ParamSet 2) and publishes the
          Poseidon root of this balance snapshot. The committee's DKG + single hybrid relin ceremony (one key for all 24
          multiplication levels) takes ~1–2 minutes on the dev stack before bidding opens.
        </p>
        <textarea
          data-testid="snapshot"
          className="mono"
          style={{ width: '100%', minHeight: 160, background: '#0b0e13', color: 'inherit', border: '1px solid var(--line)', borderRadius: 8, padding: 8 }}
          value={snapshot}
          onChange={(e) => setSnapshot(e.target.value)}
        />
        <div className="row" style={{ marginTop: 8 }}>
          <label>
            bidding window (s) <input data-testid="duration" type="number" value={duration} onChange={(e) => setDuration(Number(e.target.value))} style={{ width: 90 }} />
          </label>
          <button data-testid="open-round" disabled={open.isPending} onClick={() => open.mutate()}>
            {open.isPending ? 'requesting…' : 'Request round'}
          </button>
          {open.isError && <span className="badge bad">{String((open.error as Error).message)}</span>}
          {open.data && <span className="badge ok">E3 #{open.data.e3Id} requested</span>}
        </div>
      </div>
    </>
  )
}
