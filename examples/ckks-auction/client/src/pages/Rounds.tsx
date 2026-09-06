// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import type { BalanceEntry } from '@ckks-auction/sdk'
import { privateKeyToAddress } from 'viem/accounts'
import { RoundCard, SectionHeader, e3Num, e3Short } from '@interfold/ckks-editorial'

import { api } from '../api'
import { DEV_KEYS } from '../wallet'

const DEFAULT_SNAPSHOT: BalanceEntry[] = DEV_KEYS.map((k, i) => ({
  address: privateKeyToAddress(k.key),
  balance: ['100', '500', '1000', '1000', '1000'][i],
}))

const statusOf = (s: string): 'live' | 'closed' | 'pending' => (s === 'active' ? 'live' : s === 'requested' ? 'pending' : 'closed')

export const Rounds = () => {
  const qc = useQueryClient()
  const navigate = useNavigate()
  const rounds = useQuery({ queryKey: ['rounds'], queryFn: () => api.rounds() })
  const [snapshot, setSnapshot] = useState(JSON.stringify(DEFAULT_SNAPSHOT, null, 2))
  const [duration, setDuration] = useState(300)
  const open = useMutation({
    mutationFn: async () => api.createRound(JSON.parse(snapshot) as BalanceEntry[], duration),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rounds'] }),
  })
  const list = rounds.data ?? []

  return (
    <>
      <section className="pad-section">
        <SectionHeader num="01" kicker="ROUNDS" title="Auction rounds" meta={`${list.length} on this chain`} />
        {list.length === 0 && (
          <p className="muted" style={{ marginTop: 24 }}>
            No rounds yet — open one below.
          </p>
        )}
        <div className="grid-3" style={{ marginTop: 28 }}>
          {list.map((r) => (
            <RoundCard
              key={r.e3Id}
              testId={`round-${r.e3Id}`}
              num={e3Num(r.e3Id)}
              title={`Round ${e3Short(r.e3Id)}`}
              status={statusOf(r.status)}
              endsAtMs={r.inputWindow[1] * 1000}
              meta={`${r.bidCount} bid${r.bidCount === 1 ? '' : 's'} · ${r.status}`}
              onClick={() => navigate(`/rounds/${r.e3Id}`)}
            />
          ))}
        </div>
      </section>

      <section className="pad-section">
        <SectionHeader num="02" kicker="OPENER" title="Open a round" meta="admin" />
        <p className="muted" style={{ marginTop: 20 }}>
          The server requests an E3 through <span className="mono">CkksAuctionE3Program</span> (ParamSet 2) and publishes the Poseidon root of
          this balance snapshot. The committee's DKG + single hybrid relin ceremony (one key for all 24 multiplication levels) takes ~1–2
          minutes on the dev stack before bidding opens.
        </p>
        <div className="grid-2" style={{ marginTop: 20 }}>
          <div className="field">
            <label htmlFor="snapshot">balance snapshot — (address, balance) leaves</label>
            <textarea id="snapshot" data-testid="snapshot" style={{ minHeight: 200 }} value={snapshot} onChange={(e) => setSnapshot(e.target.value)} />
          </div>
          <div className="col" style={{ gap: 16 }}>
            <div className="field" style={{ maxWidth: 200 }}>
              <label htmlFor="duration">bidding window (s)</label>
              <input id="duration" data-testid="duration" type="number" value={duration} onChange={(e) => setDuration(Number(e.target.value))} />
            </div>
            <div className="row" style={{ gap: 12 }}>
              <button type="button" className="btn" data-testid="open-round" disabled={open.isPending} onClick={() => open.mutate()}>
                {open.isPending ? 'Requesting…' : 'Request round →'}
              </button>
              {open.isError && <span className="error">{String((open.error as Error).message)}</span>}
              {open.data && <span className="tag live dot">round {e3Short(open.data.e3Id)} requested</span>}
            </div>
          </div>
        </div>
      </section>
    </>
  )
}
