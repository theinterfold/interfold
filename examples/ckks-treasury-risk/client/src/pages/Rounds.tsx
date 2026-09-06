// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import type { Address } from 'viem'
import { privateKeyToAddress } from 'viem/accounts'
import { ASSETS, MIN_DAOS } from '@ckks-treasury/sdk'
import { RoundCard, SectionHeader, e3Num, e3Short } from '@interfold/ckks-editorial'

import { api } from '../api'
import { DEV_KEYS } from '../wallet'

/** Same as the server's `get_mock_daos` (anvil #6, #7, #8). */
export const DEFAULT_DAOS: Address[] = [0, 1, 2].map((i) => privateKeyToAddress(DEV_KEYS[i].key))
/** Same as the server's `get_mock_weights` / the contract fixture. */
export const DEFAULT_WEIGHTS: number[] = [0.5, -0.25, 1.0, 0.125]

const statusOf = (s: string): 'live' | 'closed' | 'pending' => (s === 'active' ? 'live' : s === 'requested' ? 'pending' : 'closed')

export const Rounds = () => {
  const qc = useQueryClient()
  const navigate = useNavigate()
  const rounds = useQuery({ queryKey: ['rounds'], queryFn: () => api.rounds() })
  const [weights, setWeights] = useState<string[]>(DEFAULT_WEIGHTS.map(String))
  const [daos, setDaos] = useState<string>(DEFAULT_DAOS.join('\n'))
  const [duration, setDuration] = useState(300)
  const parsedDaos = () =>
    daos
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter(Boolean) as Address[]
  const open = useMutation({
    mutationFn: async () => {
      const w = weights.map(Number)
      if (w.length !== ASSETS || w.some((x) => !Number.isFinite(x) || Math.abs(x) > 1)) throw new Error(`enter ${ASSETS} weights in [-1, 1]`)
      const d = parsedDaos()
      if (d.length < MIN_DAOS) throw new Error(`enter at least ${MIN_DAOS} DAO addresses`)
      return api.createRound(w, d, duration)
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rounds'] }),
  })
  const list = rounds.data ?? []

  return (
    <>
      <section className="pad-section">
        <SectionHeader num="01" kicker="ROUNDS" title="Risk rounds" meta={`${list.length} on this chain`} />
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
              meta={`${r.submissionCount} / ${r.daoCount} DAOs · w = [${r.weights.join(', ')}] · ${r.status}`}
              onClick={() => navigate(`/rounds/${r.e3Id}`)}
            />
          ))}
        </div>
      </section>

      <section className="pad-section">
        <SectionHeader num="02" kicker="ADMIN" title="Open a round" meta="weights + DAO list" />
        <p className="muted" style={{ marginTop: 20 }}>
          The server requests an E3 through <span className="mono">CkksTreasuryE3Program</span> (ParamSet 5, N=512, 3 limbs, coefficient
          encoding) and registers the public risk weights (<span className="mono">|wₐ| ≤ 1</span>, fixed point ×2¹⁶) and the DAO list (slot =
          position, at least {MIN_DAOS}). The committee's DKG plus the level-0 relinearization ceremony (~1 minute on the dev stack) runs before
          submissions open — the ceremony key lets the network multiply the summed encrypted books.
        </p>
        <div className="grid-2" style={{ marginTop: 20 }}>
          <div className="field">
            <label htmlFor="daos">DAOs — one address per line; slot = position</label>
            <textarea id="daos" data-testid="daos" style={{ minHeight: 160 }} value={daos} onChange={(e) => setDaos(e.target.value)} />
          </div>
          <div className="col" style={{ gap: 16 }}>
            <div className="row" style={{ gap: 12, alignItems: 'flex-end' }}>
              {weights.map((w, a) => (
                <div key={a} className="field" style={{ maxWidth: 120 }}>
                  <label htmlFor={`weight-${a}`}>w_{a}</label>
                  <input
                    id={`weight-${a}`}
                    data-testid={`weight-${a}`}
                    type="number"
                    step="0.001"
                    min={-1}
                    max={1}
                    value={w}
                    onChange={(e) => setWeights(weights.map((x, i) => (i === a ? e.target.value : x)))}
                  />
                </div>
              ))}
            </div>
            <div className="field" style={{ maxWidth: 200 }}>
              <label htmlFor="duration">submission window (s)</label>
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
