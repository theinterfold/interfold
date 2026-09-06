// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import type { ApplicantEntry, Model } from '@ckks-credit/sdk'
import { privateKeyToAddress } from 'viem/accounts'
import { RoundCard, SectionHeader, e3Num, e3Short } from '@interfold/ckks-editorial'

import { api } from '../api'
import { DEV_KEYS } from '../wallet'

/** Same as the server's `get_mock_applicants` (anvil #6, #7, #8, #9, #0). */
export const DEFAULT_FEATURES: number[][] = [
  [520, 130, 350, 999, 0, 1, 777, 42],
  [900, 850, 700, 120, 300, 640, 210, 980],
  [100, 200, 300, 400, 500, 600, 700, 800],
  [1000, 1000, 1000, 1000, 0, 0, 0, 0],
  [250, 750, 125, 875, 333, 666, 999, 1],
]
const DEFAULT_SNAPSHOT: ApplicantEntry[] = DEV_KEYS.map((k, i) => ({ address: privateKeyToAddress(k.key), features: DEFAULT_FEATURES[i] }))
export const DEFAULT_MODEL: Model = { weights: [1.5, -0.75, 2.0, 1.0, -1.25, 0.5, 0.8, -0.3], bias: -1.2 }

const statusOf = (s: string): 'live' | 'closed' | 'pending' => (s === 'active' ? 'live' : s === 'requested' ? 'pending' : 'closed')

export const Rounds = () => {
  const qc = useQueryClient()
  const navigate = useNavigate()
  const rounds = useQuery({ queryKey: ['rounds'], queryFn: () => api.rounds() })
  const [snapshot, setSnapshot] = useState(JSON.stringify(DEFAULT_SNAPSHOT, null, 2))
  const [model, setModel] = useState(JSON.stringify(DEFAULT_MODEL))
  const [duration, setDuration] = useState(300)
  const open = useMutation({
    mutationFn: async () => api.createRound(JSON.parse(snapshot) as ApplicantEntry[], JSON.parse(model) as Model, duration),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rounds'] }),
  })
  const list = rounds.data ?? []

  return (
    <>
      <section className="pad-section">
        <SectionHeader num="01" kicker="ROUNDS" title="Scoring rounds" meta={`${list.length} on this chain`} />
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
              meta={`${r.applicationCount} application${r.applicationCount === 1 ? '' : 's'} · ${r.status}`}
              onClick={() => navigate(`/rounds/${r.e3Id}`)}
            />
          ))}
        </div>
      </section>

      <section className="pad-section">
        <SectionHeader num="02" kicker="ISSUER" title="Open a round" meta="admin / issuer" />
        <p className="muted" style={{ marginTop: 20 }}>
          The server requests an E3 through <span className="mono">CkksCreditE3Program</span> (ParamSet 4, N=512, 5 limbs) and publishes the
          Poseidon root of this issuer snapshot plus the public model. The committee's DKG and two-level relinearization ceremony (~1 minute on
          the dev stack) run before applications open. Weights and bias must be in [−8, 8].
        </p>
        <div className="grid-2" style={{ marginTop: 20 }}>
          <div className="field">
            <label htmlFor="snapshot">issuer snapshot — (address, x₀..x₇) leaves</label>
            <textarea id="snapshot" data-testid="snapshot" style={{ minHeight: 200 }} value={snapshot} onChange={(e) => setSnapshot(e.target.value)} />
          </div>
          <div className="col" style={{ gap: 16 }}>
            <div className="field">
              <label htmlFor="model">public model (w, b)</label>
              <input id="model" data-testid="model" type="text" value={model} onChange={(e) => setModel(e.target.value)} />
            </div>
            <div className="field" style={{ maxWidth: 200 }}>
              <label htmlFor="duration">application window (s)</label>
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
