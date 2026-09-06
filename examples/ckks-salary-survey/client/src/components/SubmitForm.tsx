// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { ApiError, type ProveResult, type Round, type StageTiming, type SubmitResponse } from '@interfold/ckks-salary-sdk'
import { EncryptedInputCard, ProofSteps, SectionHeader, type ProofStep } from '@interfold/ckks-editorial'
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
  const [proved, setProved] = useState<ProveResult | null>(null)
  const [result, setResult] = useState<SubmitResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [duplicate, setDuplicate] = useState(false)
  const [proveMillis, setProveMillis] = useState(0)
  const [threads, setThreads] = useState<boolean | null>(null)

  const open = round.status === 'open' && !!round.public_key_hex
  const value = Number(salary)
  const busy = phase === 'proving' || phase === 'relaying'

  const push = (line: string) => setLog((l) => [...l, line])

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!round.public_key_hex) return
    setPhase('proving')
    setLog([])
    setTimings([])
    setProved(null)
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
      setProved(proved)
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

  // Proof ladder: finished stages (with ms) + the stage currently running + the relay leg.
  const steps: ProofStep[] = [
    ...timings.map((t) => ({ label: t.stage, state: 'done' as const, detail: `${t.millis} ms` })),
    ...(phase === 'proving' ? [{ label: stage || 'preparing…', state: 'running' as const }] : []),
    ...(phase === 'relaying' ? [{ label: stage, state: 'running' as const }] : []),
    ...(phase === 'done' && result ? [{ label: 'relayed · verified on-chain', state: 'done' as const, detail: `${result.relay_millis} ms` }] : []),
    ...(phase === 'error' && error ? [{ label: stage || 'failed', state: 'failed' as const }] : []),
  ]

  return (
    <section className="pad-section" data-testid="submit-form">
      <SectionHeader num="02" kicker="SUBMIT" title="Encrypt, prove, submit — from this browser" meta="3 UltraHonk legs" />
      <div className="grid-2" style={{ marginTop: 24 }}>
        <div className="col" style={{ gap: 16 }}>
          <p className="muted" style={{ margin: 0 }}>
            Your salary is normalised by the public cap, encrypted <b>in this browser</b> under the committee's joint CKKS key, and three
            zero-knowledge proofs are generated locally. Only the ciphertext and the proofs leave your machine.
          </p>
          <form onSubmit={onSubmit} className="col" style={{ gap: 14 }}>
            <div className="field" style={{ maxWidth: 320 }}>
              <label htmlFor="salary">your salary (0 – {round.salary_cap.toLocaleString()})</label>
              <input
                id="salary"
                data-testid="salary-input"
                type="number"
                min={0}
                max={round.salary_cap}
                step={1}
                placeholder={`0 – ${round.salary_cap.toLocaleString()}`}
                value={salary}
                onChange={(e) => setSalary(e.target.value)}
                disabled={!open || busy}
              />
            </div>
            <div className="row" style={{ gap: 12, flexWrap: 'wrap' }}>
              <button
                data-testid="submit-button"
                type="submit"
                className="btn lg"
                disabled={!open || !Number.isInteger(value) || value < 0 || value > round.salary_cap || busy}
              >
                {phase === 'proving' ? 'Proving…' : phase === 'relaying' ? 'Relaying…' : 'Encrypt, prove 3 legs & submit →'}
              </button>
              {!open && <span className="muted">submissions are {round.public_key_hex ? round.status : 'waiting for the committee key'}</span>}
            </div>
          </form>
          {busy && (
            <p className="mono-sm accent" data-testid="progress" style={{ margin: 0 }}>
              · {stage}
            </p>
          )}
          {result && (
            <div className="card col" style={{ gap: 8 }} data-testid="submit-result">
              <span>
                <span className="tag live dot">verified on-chain</span>
              </span>
              <div className="mono-sm">
                tx <span className="mono" data-testid="tx-hash">{result.tx_hash}</span>
              </div>
              <div className="mono-sm">
                u_commitment <span className="mono" data-testid="u-commitment">{short(result.u_commitment, 14)}</span>
              </div>
              <div className="cap">
                submission #{result.index} · gas {result.gas_used.toLocaleString()}
              </div>
            </div>
          )}
          {error && (
            <div className={duplicate ? 'cap' : 'error'} data-testid="submit-error">
              {duplicate ? 'Rejected as a duplicate: ' : 'Error: '}
              {error}
            </div>
          )}
          {log.length > 0 && (
            <details>
              <summary>prover log</summary>
              <pre className="mono-sm" data-testid="submit-log" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                {log.join('\n')}
              </pre>
            </details>
          )}
        </div>
        <div className="col" style={{ gap: 16 }}>
          {steps.length > 0 && <ProofSteps steps={steps} />}
          {proved && (
            <EncryptedInputCard
              title="salary ciphertext"
              seed={Number(BigInt(proved.uCommitment) % 100000n)}
              legs={['Greco ct0', 'Greco ct1', 'salary validity']}
              bytes={(proved.submission.ciphertextHex.length - 2) / 2}
            >
              <div className="mono-sm muted">u_commitment {short(proved.uCommitment, 12)} · m_commitment {short(proved.mCommitment, 12)}</div>
            </EncryptedInputCard>
          )}
          {timings.length > 0 && (
            <table className="ledger" data-testid="timings">
              <thead>
                <tr>
                  <th>stage</th>
                  <th>ms</th>
                </tr>
              </thead>
              <tbody>
                {timings.map((t) => (
                  <tr key={t.stage}>
                    <td className="mono">{t.stage}</td>
                    <td className="mono">{t.millis}</td>
                  </tr>
                ))}
                <tr>
                  <td>
                    <b>total proving</b> {threads === false && <span className="error">(single-threaded: no COOP/COEP)</span>}
                  </td>
                  <td className="mono">
                    <b>{proveMillis}</b>
                  </td>
                </tr>
              </tbody>
            </table>
          )}
        </div>
      </div>
    </section>
  )
}
