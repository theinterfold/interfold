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
import { D } from '@ckks-fedavg/sdk'
import { RoundCard, SectionHeader, e3Num, e3Short } from '@interfold/ckks-editorial'

import { api } from '../api'
import { DEV_KEYS } from '../wallet'

/** The four dev clients (anvil #6–#9; #0 is the round opener, 1–5 are the ciphernodes). */
export const DEFAULT_CLIENTS: Address[] = DEV_KEYS.slice(0, 4).map((k) => privateKeyToAddress(k.key))

/** Demo per-client model updates (d = 8, entries in [−1, 1]) and private sample counts. */
export const DEMO_UPDATES: { update: number[]; count: number }[] = [
  { update: [0.25, -0.5, 0.125, 0.75, -0.0625, 0.3, -0.2, 0.1], count: 120 },
  { update: [-0.1, 0.4, 0.2, -0.3, 0.5, -0.25, 0.05, 0.6], count: 40 },
  { update: [0.5, 0.5, -0.5, -0.5, 0.25, 0.25, -0.25, -0.25], count: 300 },
  { update: [0.0, -0.75, 0.35, 0.15, -0.45, 0.6, 0.7, -0.1], count: 15 },
]

export const DEFAULT_NORM_BOUND = 2.0
export const DEFAULT_MIN_CLIENTS = 3

const statusOf = (s: string): 'live' | 'closed' | 'pending' => (s === 'active' ? 'live' : s === 'requested' ? 'pending' : 'closed')

export const Rounds = () => {
  const qc = useQueryClient()
  const navigate = useNavigate()
  const rounds = useQuery({ queryKey: ['rounds'], queryFn: () => api.rounds() })
  const [clients, setClients] = useState(JSON.stringify(DEFAULT_CLIENTS, null, 2))
  const [normBound, setNormBound] = useState(DEFAULT_NORM_BOUND)
  const [minClients, setMinClients] = useState(DEFAULT_MIN_CLIENTS)
  const [duration, setDuration] = useState(300)
  const open = useMutation({
    mutationFn: async () => api.createRound(JSON.parse(clients) as Address[], { d: D, normBound, minClients }, duration),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rounds'] }),
  })
  const list = rounds.data ?? []

  return (
    <>
      <section className="pad-section">
        <SectionHeader num="01" kicker="ROUNDS" title="Averaging rounds" meta={`${list.length} on this chain`} />
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
              meta={`${r.updateCount} update${r.updateCount === 1 ? '' : 's'} · d=${r.d} · ‖g‖² ≤ ${r.normBound} · min ${r.minClients} · ${r.status}`}
              onClick={() => navigate(`/rounds/${r.e3Id}`)}
            />
          ))}
        </div>
      </section>

      <section className="pad-section">
        <SectionHeader num="02" kicker="AGGREGATOR" title="Open a round" meta="admin / aggregator" />
        <p className="muted" style={{ marginTop: 20 }}>
          The server requests an E3 through <span className="mono">CkksFedAvgE3Program</span> (ParamSet 5, N=512, 3 limbs) and registers the
          client list (your slot = your position), the public squared-norm bound <span className="mono">‖g‖² ≤ B</span> every update must prove
          against (the poisoning bound) and the public minimum client count the server enforces before evaluating. The committee's DKG plus a
          level-0 relinearization ceremony runs before updates open — the ceremony key lets the network multiply each encrypted count by its
          encrypted update. The dimension d = {D} is compiled into the validity circuit.
        </p>
        <div className="grid-2" style={{ marginTop: 20 }}>
          <div className="field">
            <label htmlFor="clients">client list — addresses in slot order</label>
            <textarea id="clients" data-testid="clients" style={{ minHeight: 200 }} value={clients} onChange={(e) => setClients(e.target.value)} />
          </div>
          <div className="col" style={{ gap: 16 }}>
            <div className="row" style={{ gap: 16, flexWrap: 'wrap' }}>
              <div className="field" style={{ maxWidth: 160 }}>
                <label htmlFor="norm-bound">norm bound B</label>
                <input id="norm-bound" data-testid="norm-bound" type="number" step="0.01" value={normBound} onChange={(e) => setNormBound(Number(e.target.value))} />
              </div>
              <div className="field" style={{ maxWidth: 140 }}>
                <label htmlFor="min-clients">min clients</label>
                <input id="min-clients" data-testid="min-clients" type="number" value={minClients} onChange={(e) => setMinClients(Number(e.target.value))} />
              </div>
              <div className="field" style={{ maxWidth: 200 }}>
                <label htmlFor="duration">update window (s)</label>
                <input id="duration" data-testid="duration" type="number" value={duration} onChange={(e) => setDuration(Number(e.target.value))} />
              </div>
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
