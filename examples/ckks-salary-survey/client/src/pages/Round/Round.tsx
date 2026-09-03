// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import { useRound } from '@/hooks/useRounds'
import { useSurvey } from '@/context/SurveyContext'
import { StatusTimeline, statusLabel } from '@/components/StatusTimeline'
import { SubmitForm } from '@/components/SubmitForm'
import { SubmissionsTable } from '@/components/SubmissionsTable'
import { ResultsPanel } from '@/components/ResultsPanel'
import { short } from '@/utils/constants'

const RoundPage = () => {
  const { e3Id } = useParams()
  const round = useRound(e3Id)
  const { api } = useSurvey()
  const qc = useQueryClient()
  const [evalError, setEvalError] = useState<string | null>(null)
  const [evaluating, setEvaluating] = useState(false)

  if (round.isLoading) return <div className="page muted">Loading round…</div>
  if (round.isError || !round.data) return <div className="page err">Round not found.</div>
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
  return (
    <div className="page">
      <Link to="/rounds" className="muted">
        ← all rounds
      </Link>
      <div className="row between">
        <h1>Round #{r.e3_id}</h1>
        <span className={`pill ${r.status}`} data-testid="round-status">
          {statusLabel(r.status)}
        </span>
      </div>
      <div className="grid">
        <section className="card">
          <h3>Status</h3>
          <StatusTimeline round={r} />
          <dl className="kv">
            <dt>program</dt>
            <dd>
              <code>{r.program_address}</code>
            </dd>
            <dt>param set</dt>
            <dd>{r.param_set} (CKKS statistics: N=512, 3 limbs, Δ=2⁴⁰)</dd>
            <dt>salary cap</dt>
            <dd>{r.salary_cap.toLocaleString()}</dd>
            <dt>committee</dt>
            <dd>{r.committee.length ? r.committee.map((c) => short(c, 8)).join(', ') : '— (forming)'}</dd>
            <dt>joint pk</dt>
            <dd data-testid="pubkey">{pk ? `${(pk.length - 2) / 2} bytes · ${short(pk, 12)}` : 'not yet published'}</dd>
          </dl>
          {['open', 'closed'].includes(r.status) && r.submissions.length > 0 && !r.evaluation && (
            <div>
              <button onClick={evaluate} disabled={evaluating} data-testid="evaluate">
                {evaluating ? 'Evaluating…' : 'Evaluate & publish (admin)'}
              </button>
              {evalError && <div className="err">{evalError}</div>}
            </div>
          )}
        </section>
        <SubmitForm round={r} />
      </div>
      <ResultsPanel round={r} />
      <SubmissionsTable round={r} />
    </div>
  )
}

export default RoundPage
