// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import { useRounds } from '@/hooks/useRounds'
import { useSurvey } from '@/context/SurveyContext'
import { statusLabel } from '@/components/StatusTimeline'
import { fmtTime } from '@/utils/constants'

const Rounds = () => {
  const rounds = useRounds()
  const { api } = useSurvey()
  const qc = useQueryClient()
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

  return (
    <div className="page">
      <div className="row between">
        <h1>Rounds</h1>
        <button onClick={create} disabled={creating} data-testid="create-round">
          {creating ? 'Requesting…' : 'New round (admin)'}
        </button>
      </div>
      {error && <div className="err">{error}</div>}
      {rounds.isLoading && <p className="muted">Loading…</p>}
      {rounds.isError && <p className="err">Server unreachable: {String(rounds.error)}</p>}
      {rounds.data && rounds.data.length === 0 && <p className="muted">No rounds yet — request one.</p>}
      <ul className="rounds" data-testid="rounds-list">
        {rounds.data?.map((r) => (
          <li key={r.e3_id} className="card">
            <Link to={`/rounds/${r.e3_id}`} data-testid={`round-${r.e3_id}`}>
              <b>Round #{r.e3_id}</b>
            </Link>
            <span className={`pill ${r.status}`}>{statusLabel(r.status)}</span>
            <span className="muted">
              {r.submission_count} submissions · cap {r.salary_cap.toLocaleString()} · window {fmtTime(r.input_window[0])}–
              {fmtTime(r.input_window[1])}
            </span>
          </li>
        ))}
      </ul>
    </div>
  )
}

export default Rounds
