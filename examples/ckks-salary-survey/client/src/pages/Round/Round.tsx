// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import { SectionHeader, e3Short, e3Num } from '@interfold/ckks-editorial'
import { useRound } from '@/hooks/useRounds'
import { useSurvey } from '@/context/SurveyContext'
import { StatusTimeline, statusLabel } from '@/components/StatusTimeline'
import { SubmitForm } from '@/components/SubmitForm'
import { SubmissionsTable } from '@/components/SubmissionsTable'
import { ResultsPanel } from '@/components/ResultsPanel'
import { fmtTime, short } from '@/utils/constants'

const RoundPage = () => {
  const { e3Id } = useParams()
  const round = useRound(e3Id)
  const { api } = useSurvey()
  const qc = useQueryClient()
  const [evalError, setEvalError] = useState<string | null>(null)
  const [evaluating, setEvaluating] = useState(false)

  if (round.isLoading)
    return (
      <section className="pad-section">
        <p className="muted">Loading round…</p>
      </section>
    )
  if (round.isError || !round.data)
    return (
      <section className="pad-section">
        <p className="error">Round not found.</p>
      </section>
    )
  const r = round.data

  const evaluate = async () => {
    setEvaluating(true)
    setEvalError(null)
    try {
      await api.evaluate(r.e3_id)
      qc.invalidateQueries({ queryKey: ['round', r.e3_id] })
    } catch (e) {
      setEvalError(e instanceof Error ? e.message : String(e))
    } finally {
      setEvaluating(false)
    }
  }

  const pk = r.public_key_hex
  const tagCls = r.status === 'open' ? 'live' : r.status === 'complete' || r.status === 'failed' ? 'closed' : ''
  return (
    <>
      <section className="pad-section">
        <Link to="/rounds" className="mono-sm muted">
          ← all rounds
        </Link>
        <div style={{ marginTop: 16 }}>
          <SectionHeader
            num={e3Num(r.e3_id)}
            kicker="ROUND"
            title={
              <>
                Round {e3Short(r.e3_id)}{' '}
                <span className={`tag dot ${tagCls}`} data-testid="round-status">
                  {statusLabel(r.status)}
                </span>
              </>
            }
            meta={
              <>
                window {fmtTime(r.input_window[0])} → {fmtTime(r.input_window[1])}
              </>
            }
          />
        </div>
        <div className="col" style={{ gap: 20, marginTop: 24 }}>
          <StatusTimeline round={r} />
          {r.failure_reason && <div className="error">{r.failure_reason}</div>}
        </div>

        <div className="grid-2" style={{ marginTop: 28 }}>
          <div className="card col" style={{ gap: 10 }}>
            <div className="mono muted">Deployment</div>
            <div className="mono">program {r.program_address}</div>
            <div className="mono">ParamSet {r.param_set} · N=512 · 3 limbs · Δ=2⁴⁰</div>
            <div className="mono">salary cap {r.salary_cap.toLocaleString()}</div>
            <div className="cap">
              committee key {pk ? 'published' : 'DKG + relin ceremony in progress'} · Σx and Σx² computed on ciphertext (1 ct×ct, packed)
            </div>
          </div>
          <div className="card col" style={{ gap: 10 }}>
            <div className="mono muted">Committee</div>
            <div className="mono">{r.committee.length ? r.committee.map((c) => short(c, 8)).join(', ') : '— (forming)'}</div>
            <div className="mono muted" style={{ marginTop: 6 }}>
              Joint public key
            </div>
            <div className="mono" data-testid="pubkey">
              {pk ? `${(pk.length - 2) / 2} bytes · ${short(pk, 12)}` : 'not yet published'}
            </div>
            {['open', 'closed'].includes(r.status) && r.submissions.length > 0 && !r.evaluation && (
              <div className="row" style={{ gap: 12, marginTop: 8 }}>
                <button type="button" className="btn ghost" onClick={evaluate} disabled={evaluating} data-testid="evaluate">
                  {evaluating ? 'Evaluating…' : 'Evaluate & publish (admin)'}
                </button>
                {evalError && <span className="error">{evalError}</span>}
              </div>
            )}
          </div>
        </div>
      </section>
      <SubmitForm round={r} />
      <SubmissionsTable round={r} />
      <ResultsPanel round={r} />
    </>
  )
}

export default RoundPage
