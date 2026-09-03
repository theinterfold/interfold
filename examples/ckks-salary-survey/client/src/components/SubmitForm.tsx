// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { ApiError, type Round, type StageTiming, type SubmitResponse } from '@interfold/ckks-salary-sdk'
import { useSurvey } from '@/context/SurveyContext'
import { proveInBrowser } from '@/lib/prover'
import { short } from '@/utils/constants'

interface Props {
  round: Round
}

type Phase = 'idle' | 'proving' | 'relaying' | 'done' | 'error'

export const SubmitForm = ({ round }: Props) => {
  const { api } = useSurvey()
  const qc = useQueryClient()
  const [salary, setSalary] = useState('')
  const [phase, setPhase] = useState<Phase>('idle')
  const [stage, setStage] = useState('')
  const [log, setLog] = useState<string[]>([])
  const [timings, setTimings] = useState<StageTiming[]>([])
  const [result, setResult] = useState<SubmitResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [duplicate, setDuplicate] = useState(false)
  const [proveMillis, setProveMillis] = useState(0)
  const [threads, setThreads] = useState<boolean | null>(null)

  const open = round.status === 'open' && !!round.public_key_hex
  const value = Number(salary)

  const push = (line: string) => setLog((l) => [...l, line])

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!round.public_key_hex) return
    setPhase('proving')
    setLog([])
    setTimings([])
    setResult(null)
    setError(null)
    setDuplicate(false)
    try {
      const proved = await proveInBrowser(round.public_key_hex, value, round.salary_cap, (s, d) => {
        setStage(s)
        push(d ? `${s} — ${d}` : s)
      })
      setTimings(proved.timings)
      setProveMillis(proved.totalMillis)
      setThreads(proved.threads)
      push(`u_commitment ${proved.uCommitment}`)
      push(`m_commitment ${proved.mCommitment}`)
      setPhase('relaying')
      setStage('relaying to the on-chain gate (server pays gas)')
      const res = await api.submit(round.e3_id, proved.submission)
      setResult(res)
      push(`ACCEPTED on-chain: tx ${res.tx_hash} (gas ${res.gas_used}, ${res.relay_millis} ms)`)
      setPhase('done')
      qc.invalidateQueries({ queryKey: ['round', round.e3_id] })
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      setError(msg)
      setDuplicate(err instanceof ApiError && err.duplicate)
      setPhase('error')
    }
  }

  return (
    <section className="card" data-testid="submit-form">
      <h3>Submit your salary</h3>
      <p className="muted">
        Your salary is encrypted <b>in this browser</b> under the committee's joint CKKS key, and three
        zero-knowledge proofs are generated locally. Only the ciphertext and the proofs leave your machine.
      </p>
      <form onSubmit={onSubmit} className="row">
        <input
          data-testid="salary-input"
          type="number"
          min={0}
          max={round.salary_cap}
          step={1}
          placeholder={`0 – ${round.salary_cap.toLocaleString()}`}
          value={salary}
          onChange={(e) => setSalary(e.target.value)}
          disabled={!open || phase === 'proving' || phase === 'relaying'}
        />
        <button
          data-testid="submit-button"
          type="submit"
          disabled={!open || !Number.isInteger(value) || value < 0 || value > round.salary_cap || phase === 'proving' || phase === 'relaying'}
        >
          {phase === 'proving' ? 'Proving…' : phase === 'relaying' ? 'Relaying…' : 'Encrypt, prove & submit'}
        </button>
      </form>
      {!open && <p className="warn">Submissions are {round.public_key_hex ? round.status : 'waiting for the committee key'}.</p>}
      {(phase === 'proving' || phase === 'relaying') && (
        <p className="progress" data-testid="progress">
          <span className="spinner" /> {stage}
        </p>
      )}
      {log.length > 0 && (
        <pre className="log" data-testid="submit-log">
          {log.join('\n')}
        </pre>
      )}
      {timings.length > 0 && (
        <table className="timings" data-testid="timings">
          <thead>
            <tr>
              <th>stage</th>
              <th>ms</th>
            </tr>
          </thead>
          <tbody>
            {timings.map((t) => (
              <tr key={t.stage}>
                <td>{t.stage}</td>
                <td>{t.millis}</td>
              </tr>
            ))}
            <tr>
              <td>
                <b>total proving</b> {threads === false && <span className="warn">(single-threaded: no COOP/COEP)</span>}
              </td>
              <td>
                <b>{proveMillis}</b>
              </td>
            </tr>
          </tbody>
        </table>
      )}
      {result && (
        <div className="ok" data-testid="submit-result">
          <span className="badge">✓ verified on-chain</span>
          <div>
            tx <code data-testid="tx-hash">{result.tx_hash}</code>
          </div>
          <div>
            u_commitment <code data-testid="u-commitment">{short(result.u_commitment, 14)}</code>
          </div>
          <div>submission #{result.index}, gas {result.gas_used.toLocaleString()}</div>
        </div>
      )}
      {error && (
        <div className={duplicate ? 'warn' : 'err'} data-testid="submit-error">
          {duplicate ? 'Rejected as a duplicate: ' : 'Error: '}
          {error}
        </div>
      )}
    </section>
  )
}
