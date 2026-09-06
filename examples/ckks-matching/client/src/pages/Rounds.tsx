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
import { RoundCard, SectionHeader, e3Num, e3Short } from '@interfold/ckks-editorial'

import { api } from '../api'
import { DEV_KEYS } from '../wallet'

/** Same as the server's `get_mock_parties` (anvil #6 = A, #7 = B). */
export const DEFAULT_PARTY_A: Address = privateKeyToAddress(DEV_KEYS[0].key)
export const DEFAULT_PARTY_B: Address = privateKeyToAddress(DEV_KEYS[1].key)

const statusOf = (s: string): 'live' | 'closed' | 'pending' => (s === 'active' ? 'live' : s === 'requested' ? 'pending' : 'closed')

export const Rounds = () => {
  const qc = useQueryClient()
  const navigate = useNavigate()
  const rounds = useQuery({ queryKey: ['rounds'], queryFn: () => api.rounds() })
  const [partyA, setPartyA] = useState<string>(DEFAULT_PARTY_A)
  const [partyB, setPartyB] = useState<string>(DEFAULT_PARTY_B)
  const [duration, setDuration] = useState(300)
  const open = useMutation({
    mutationFn: async () => api.createRound(partyA as Address, partyB as Address, duration),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rounds'] }),
  })
  const list = rounds.data ?? []

  return (
    <>
      <section className="pad-section">
        <SectionHeader num="01" kicker="ROUNDS" title="Matching rounds" meta={`${list.length} on this chain`} />
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
              meta={`${r.partyA.slice(0, 8)}… / ${r.partyB.slice(0, 8)}… · ${r.submissionCount} / 2 · ${r.status}`}
              onClick={() => navigate(`/rounds/${r.e3Id}`)}
            />
          ))}
        </div>
      </section>

      <section className="pad-section">
        <SectionHeader num="02" kicker="ADMIN" title="Open a round" meta="admin" />
        <p className="muted" style={{ marginTop: 20 }}>
          The server requests an E3 through <span className="mono">CkksMatchingE3Program</span> (ParamSet 5, N=512, 3 limbs, coefficient encoding)
          and registers exactly two parties: slot 0 = A (<span className="mono">forward</span> layout), slot 1 = B (
          <span className="mono">reversed</span> layout). The committee's DKG plus the level-0 relinearization ceremony (~1 minute on the dev
          stack) runs before submissions open — the ceremony key lets the network multiply the two encrypted vectors.
        </p>
        <div className="grid-2" style={{ marginTop: 20 }}>
          <div className="col" style={{ gap: 16 }}>
            <div className="field">
              <label htmlFor="party-a">party A — slot 0, forward layout</label>
              <input id="party-a" data-testid="party-a" type="text" value={partyA} onChange={(e) => setPartyA(e.target.value)} />
            </div>
            <div className="field">
              <label htmlFor="party-b">party B — slot 1, reversed layout</label>
              <input id="party-b" data-testid="party-b" type="text" value={partyB} onChange={(e) => setPartyB(e.target.value)} />
            </div>
          </div>
          <div className="col" style={{ gap: 16 }}>
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
