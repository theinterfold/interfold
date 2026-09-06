// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import { RoundCard, SectionHeader, e3Short, e3Num } from '@interfold/ckks-editorial'
import { useRounds } from '@/hooks/useRounds'
import { useSurvey } from '@/context/SurveyContext'
import { statusLabel } from '@/components/StatusTimeline'
import { fmtTime } from '@/utils/constants'

const statusOf = (s: string): 'live' | 'closed' | 'pending' => (s === 'open' ? 'live' : s === 'requested' ? 'pending' : 'closed')

const Rounds = () => {
  const rounds = useRounds()
  const { api } = useSurvey()
  const qc = useQueryClient()
  const navigate = useNavigate()
  const [creating, setCreating] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const create = async () => {
    setCreating(true)
    setError(null)
    try {
      await api.createRound()
      qc.invalidateQueries({ queryKey: ['rounds'] })
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setCreating(false)
    }
  }

  const list = rounds.data ?? []

  return (
    <>
      <section className="pad-section">
        <SectionHeader num="01" kicker="ROUNDS" title="Survey rounds" meta={`${list.length} on this chain`} />
        {rounds.isLoading && (
          <p className="muted" style={{ marginTop: 24 }}>
            Loading…
          </p>
        )}
        {rounds.isError && (
          <p className="error" style={{ marginTop: 24 }}>
            Server unreachable: {String(rounds.error)}
          </p>
        )}
        {rounds.data && rounds.data.length === 0 && (
          <p className="muted" style={{ marginTop: 24 }}>
            No rounds yet — request one below.
          </p>
        )}
        <div className="grid-3" style={{ marginTop: 28 }} data-testid="rounds-list">
          {list.map((r) => (
            <RoundCard
              key={r.e3_id}
              testId={`round-${r.e3_id}`}
              num={e3Num(r.e3_id)}
              title={`Round ${e3Short(r.e3_id)}`}
              status={statusOf(r.status)}
              endsAtMs={r.input_window[1] * 1000}
              meta={
                <span className="col" style={{ gap: 4 }}>
                  <span>
                    {r.submission_count} submission{r.submission_count === 1 ? '' : 's'} · cap {r.salary_cap.toLocaleString()}
                  </span>
                  <span>
                    {statusLabel(r.status)} · {fmtTime(r.input_window[0])}–{fmtTime(r.input_window[1])}
                  </span>
                </span>
              }
              onClick={() => navigate(`/rounds/${r.e3_id}`)}
            />
          ))}
        </div>
      </section>

      <section className="pad-section">
        <SectionHeader num="02" kicker="ADMIN" title="Open a round" meta="admin key" />
        <p className="muted" style={{ marginTop: 20 }}>
          The server requests an E3 through <span className="mono">CkksSalaryE3Program</span> (ParamSet 3, N=512, 3 limbs). The committee's DKG and
          relinearisation ceremony run before submissions open.
        </p>
        <div className="row" style={{ gap: 12, marginTop: 20 }}>
          <button type="button" className="btn" onClick={create} disabled={creating} data-testid="create-round">
            {creating ? 'Requesting…' : 'New round (admin) →'}
          </button>
          {error && <span className="error">{error}</span>}
        </div>
      </section>
    </>
  )
}

export default Rounds
