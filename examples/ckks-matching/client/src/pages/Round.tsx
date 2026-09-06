// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { getAddress } from 'viem'
import type { RoundDetail, Role, SlotResponse } from '@ckks-matching/sdk'
import { K, PARTIES, roleLayout } from '@ckks-matching/sdk'
import { EncryptedInputCard, HonestScope, ProofSteps, ResultCard, RoundTimeline, SectionHeader, type ProofStep, type RoundPhase, e3Num, e3Short } from '@interfold/ckks-editorial'

import { api } from '../api'
import { loadSubmission, useApply } from '../hooks/useApply'
import { useWallet } from '../wallet'

/** Map the server's round status onto the editorial timeline. */
const phaseOf = (r: RoundDetail): RoundPhase => {
  if (r.status === 'failed') return 'failed'
  if (r.status === 'finished') return 'published'
  if (r.status === 'published') return 'decrypting'
  if (r.status === 'evaluating') return 'evaluating'
  if (r.status === 'active') return r.publicKeyAvailable ? 'open' : 'ceremony'
  return 'keygen'
}

const fmtTime = (s: number) => new Date(s * 1000).toLocaleTimeString()

/** Demo profile vectors (raw, cap 100): the fixture vectors of `gen_ckks_matching_prover` ×100 — score ≈ −2.4275. */
export const DEMO_CAP = 100
export const DEMO_A: number[] = [50, -25, 100, -100, 12.5, 0, 75, -50, 30, -70, 90, -10, 60, 20, -40, 5]
export const DEMO_B: number[] = [40, 30, -20, 90, -100, 100, 10, 50, -60, 80, 25, 75, -35, 15, 95, -5]

export const Round = () => {
  const { id = '' } = useParams()
  const qc = useQueryClient()
  const round = useQuery({ queryKey: ['round', id], queryFn: () => api.round(id), refetchInterval: 3000 })
  const evaluate = useMutation({ mutationFn: () => api.evaluate(id), onSuccess: () => qc.invalidateQueries({ queryKey: ['round', id] }) })
  if (round.isLoading || !round.data)
    return (
      <section className="pad-section">
        <p className="muted">loading round {e3Short(id)}…</p>
      </section>
    )
  const r = round.data
  const phase = phaseOf(r)
  return (
    <>
      <section className="pad-section">
        <SectionHeader
          num={e3Num(r.e3Id)}
          kicker="ROUND"
          title={
            <>
              Round {e3Short(r.e3Id)}{' '}
              <span className={`tag dot ${r.status === 'active' ? 'live' : r.status === 'finished' || r.status === 'failed' ? 'closed' : ''}`} data-testid="round-status">
                {r.status}
              </span>
            </>
          }
          meta={
            <>
              window {fmtTime(r.inputWindow[0])} → {fmtTime(r.inputWindow[1])}
            </>
          }
        />
        <div className="col" style={{ gap: 20, marginTop: 24 }}>
          <RoundTimeline phase={phase} committee={{ signed: r.publicKeyAvailable ? 5 : 0, total: 5 }} testId="round-timeline" />
          {r.error && <div className="error">{r.error}</div>}
        </div>

        <div className="grid-2" style={{ marginTop: 28 }}>
          <div className="card col" style={{ gap: 10 }}>
            <div className="mono muted">Deployment</div>
            <div className="mono">program {r.programAddress}</div>
            <div className="mono">ParamSet {r.paramSet} · N=512 · 3 limbs · Δ=2⁴⁰ · k = {r.k}</div>
            <div className="cap">
              committee key {r.publicKeyAvailable ? 'published' : 'DKG + level-0 relin ceremony in progress'} · ⟨a, b⟩ computed on the encrypted vectors (1 ct×ct)
            </div>
          </div>
          <div className="card col" style={{ gap: 10 }}>
            <div className="mono muted">Registered parties (slot = role)</div>
            <table className="ledger">
              <tbody>
                {r.parties.map((a, i) => (
                  <tr key={a}>
                    <td className="mono">{i}</td>
                    <td>{i === 0 ? 'A · forward' : 'B · reversed'}</td>
                    <td className="mono">{a}</td>
                    <td>{r.submissions.some((s) => s.index === i) ? <span className="tag live">submitted</span> : <span className="muted">waiting</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <SubmitPanel round={r} />

      <section className="pad-section">
        <SectionHeader num="03" kicker="LEDGER" title="Accepted submissions" meta={`${r.submissions.length} / ${PARTIES} verified on-chain`} />
        <table className="ledger" style={{ marginTop: 20 }}>
          <thead>
            <tr>
              <th>slot</th>
              <th>role</th>
              <th>party</th>
              <th>tx</th>
              <th>m_commitment (vec / mask)</th>
              <th>cts</th>
            </tr>
          </thead>
          <tbody>
            {r.submissions.map((b) => (
              <tr key={b.transactionHash} data-testid="submission-row">
                <td className="mono">{b.index}</td>
                <td>
                  {b.role.toUpperCase()} · {roleLayout(b.role)}
                </td>
                <td className="mono">{b.publisher}</td>
                <td className="mono">{b.transactionHash.slice(0, 14)}…</td>
                <td className="mono">
                  {b.mCommitmentVec.slice(0, 10)}… / {b.mCommitmentMask.slice(0, 10)}…
                </td>
                <td>{b.ciphertextAvailable ? <span className="tag live">verified on-chain</span> : <span className="tag closed">missing</span>}</td>
              </tr>
            ))}
            {r.submissions.length === 0 && (
              <tr>
                <td colSpan={6} className="muted">
                  none yet
                </td>
              </tr>
            )}
          </tbody>
        </table>
        {(r.status === 'active' || r.status === 'evaluating') && r.submissions.length >= PARTIES && (
          <div className="row" style={{ marginTop: 16, gap: 12 }}>
            <button type="button" className="btn ghost" data-testid="evaluate" disabled={evaluate.isPending} onClick={() => evaluate.mutate()}>
              {evaluate.isPending ? 'Evaluating…' : 'Evaluate now (admin)'}
            </button>
            {evaluate.isError && <span className="error">{(evaluate.error as Error).message}</span>}
          </div>
        )}
        {r.status === 'active' && r.submissions.length < PARTIES && (
          <p className="muted" style={{ marginTop: 16 }}>
            the server evaluates automatically as soon as both parties have submitted
          </p>
        )}
      </section>

      {r.results && <Results round={r} />}

      {Object.keys(r.timings).length > 0 && (
        <section className="pad-section">
          <details>
            <summary>timings</summary>
            <table className="ledger" style={{ marginTop: 12 }}>
              <tbody>
                {Object.entries(r.timings).map(([k, v]) => (
                  <tr key={k}>
                    <td className="mono">{k}</td>
                    <td className="mono">{v}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </details>
        </section>
      )}
    </>
  )
}

const SubmitPanel = ({ round }: { round: RoundDetail }) => {
  const { address } = useWallet()
  const { state, submit } = useApply(round.e3Id, round.programAddress)
  const [slot, setSlot] = useState<SlotResponse | null>(null)
  const registeredIndex = address ? round.parties.findIndex((a) => getAddress(a) === getAddress(address)) : -1
  const registered = registeredIndex >= 0
  const defaultRaw = registeredIndex === 1 ? DEMO_B : DEMO_A
  const [raw, setRaw] = useState(JSON.stringify(defaultRaw))
  const [cap, setCap] = useState(DEMO_CAP)
  const [roleOverride, setRoleOverride] = useState<'' | Role>('')
  const alreadySubmitted = address ? round.submissions.some((b) => getAddress(b.publisher) === getAddress(address)) : false
  const canSubmit = round.status === 'active' && round.publicKeyAvailable && registered && !alreadySubmitted && !state.running

  useEffect(() => {
    setSlot(null)
    if (!address || !registered) return
    api.slot(round.e3Id, address).then(setSlot).catch(() => setSlot(null))
    setRaw(JSON.stringify(registeredIndex === 1 ? DEMO_B : DEMO_A))
  }, [address, registered, registeredIndex, round.e3Id])

  const parsedRaw = (): number[] => {
    const v = JSON.parse(raw) as number[]
    if (!Array.isArray(v) || v.length !== K) throw new Error(`the profile vector must have exactly ${K} entries`)
    return v
  }

  const steps: ProofStep[] = state.steps.map((s) => ({
    label: s.label,
    state: s.status === 'running' ? 'running' : s.status === 'done' ? 'done' : 'failed',
    detail: s.ms !== undefined ? `${Math.round(s.ms)} ms` : undefined,
  }))

  return (
    <section className="pad-section">
      <SectionHeader num="02" kicker="SUBMIT" title="Encrypt, prove, submit — from this browser" meta="5 UltraHonk legs" />
      <div className="grid-2" style={{ marginTop: 24 }}>
        <div className="col" style={{ gap: 16 }}>
          {!address && (
            <p className="muted">
              Connect a wallet to submit. Your profile vector and your cross-term mask are encrypted and proven in this browser and sent from your
              own key.
            </p>
          )}
          {address && !registered && <p className="error">{address} is not a registered party of this round</p>}
          {address && registered && slot && (
            <div className="card col" style={{ gap: 8 }}>
              <div className="mono muted">Your registered slot</div>
              <div>
                You are party <b data-testid="my-role">{slot.role.toUpperCase()}</b> (slot <span data-testid="my-index">{slot.index}</span>) · layout{' '}
                <span className="mono" data-testid="my-layout">
                  {slot.layout}
                </span>{' '}
                · address <span className="mono">{address}</span>.
              </div>
              {alreadySubmitted && <span className="tag">you already submitted in this round</span>}
            </div>
          )}
          <div className="field">
            <label htmlFor="vector">profile vector ({K} raw values, cap-normalised to [−1, 1] by dividing by the cap)</label>
            <input id="vector" data-testid="vector" type="text" value={raw} onChange={(e) => setRaw(e.target.value)} />
          </div>
          <div className="field" style={{ maxWidth: 200 }}>
            <label htmlFor="cap">cap</label>
            <input id="cap" data-testid="cap" type="number" value={cap} onChange={(e) => setCap(Number(e.target.value))} />
          </div>
          <div className="row" style={{ gap: 12 }}>
            <button
              type="button"
              className="btn lg"
              data-testid="submit"
              disabled={!canSubmit}
              onClick={() => {
                try {
                  submit(parsedRaw(), cap, roleOverride === '' ? undefined : roleOverride).catch(() => {})
                } catch (e) {
                  alert((e as Error).message)
                }
              }}
            >
              {state.running ? 'Proving…' : `Encrypt ${slot ? slot.layout : 'vector'} + mask, prove 5 legs & submit →`}
            </button>
            {round.status !== 'active' && (
              <span className="muted">submissions are {round.status === 'requested' ? 'not open yet (DKG + ceremony running)' : 'closed'}</span>
            )}
          </div>
          <details>
            <summary>dev: prove the WRONG layout (the contract must reject it with WrongRole)</summary>
            <select data-testid="role-override" style={{ marginTop: 8 }} value={roleOverride} onChange={(e) => setRoleOverride(e.target.value as '' | Role)}>
              <option value="">use my registered role</option>
              <option value="a">force role A (forward)</option>
              <option value="b">force role B (reversed)</option>
            </select>
          </details>
          {state.error && (
            <p className="error" data-testid="submit-error">
              {state.error}
            </p>
          )}
          {state.txHash && (
            <p>
              <span className="tag live" data-testid="submit-verified">
                verified on-chain
              </span>{' '}
              tx <span className="mono hex">{state.txHash}</span> · gas{' '}
              <span className="mono hex" data-testid="submit-gas">
                {state.gasUsed?.toString()}
              </span>
            </p>
          )}
        </div>
        <div className="col" style={{ gap: 16 }}>
          {steps.length > 0 && <ProofSteps steps={steps} testId="submit-steps" />}
          {state.submission && (
            <>
              <EncryptedInputCard
                title={`${roleLayout(state.submission.role)} vector ciphertext`}
                seed={Number(BigInt(state.submission.uCommitmentVec) % 100000n)}
                legs={['Greco ct0', 'Greco ct1', 'matching layout']}
                bytes={(state.submission.ciphertextVec.length - 2) / 2}
              >
                <div className="mono-sm muted">fixed-point entries (×2¹⁶, kept in this browser) {JSON.stringify(state.submission.fixedPoint)}</div>
              </EncryptedInputCard>
              <EncryptedInputCard
                title="cross-term mask ciphertext"
                seed={Number(BigInt(state.submission.uCommitmentMask) % 100000n)}
                legs={['Greco ct0', 'Greco ct1']}
                bytes={(state.submission.ciphertextMask.length - 2) / 2}
              >
                <div className="mono-sm muted">128 uniform integers in [0, 1024) on coefficients 1…128 (kept in this browser)</div>
              </EncryptedInputCard>
              <details>
                <summary>proof details</summary>
                <div className="mono-sm">
                  slot {state.submission.index} · role {state.submission.role.toUpperCase()} ({roleLayout(state.submission.role)})
                </div>
                <div className="mono-sm">
                  u_commitment vec {state.submission.uCommitmentVec} · mask {state.submission.uCommitmentMask}
                </div>
                <div className="mono-sm">
                  m_commitment vec {state.submission.mCommitmentVec} · mask {state.submission.mCommitmentMask}
                </div>
                <div className="mono-sm">
                  ciphertexts {(state.submission.ciphertextVec.length - 2) / 2} + {(state.submission.ciphertextMask.length - 2) / 2} bytes
                </div>
                <pre className="mono-sm hex" data-testid="submit-timings">
                  {JSON.stringify(state.submission.timings, null, 1)}
                </pre>
              </details>
            </>
          )}
        </div>
      </div>
    </section>
  )
}

const Results = ({ round }: { round: RoundDetail }) => {
  const { address } = useWallet()
  const res = round.results!
  const stored = address ? loadSubmission(round.e3Id, address) : null
  return (
    <section className="pad-section">
      <SectionHeader num="04" kicker="OPENED" title="One ciphertext, threshold-decrypted" meta="c₀ = −⟨a, b⟩ · c₁… masked" />
      <div className="grid-2" style={{ marginTop: 24 }}>
        <div className="col" style={{ gap: 16 }}>
          <ResultCard
            testId="score-card"
            label="Compatibility score ⟨a, b⟩ — computed by the network; both parties see it"
            value={<span data-testid="score">{res.score.toFixed(4)}</span>}
            caption={
              <>
                opened c₀ = <span className="mono">{res.opened[0]?.toFixed(4)}</span> → score = −c₀ (the <span className="mono">tᴺ ≡ −1</span> wrap; the
                app negates)
              </>
            }
            reveals="The similarity ⟨a, b⟩ of the two cap-normalised vectors — the same number to both parties."
            hides="Either profile vector, either mask, and every cross term a_i·b_j: coefficients 1… are hidden by both parties' masks and say nothing."
          />
          {stored && (
            <p className="muted">
              your own vector (kept in this browser, role {stored.role.toUpperCase()}): <span className="mono">{JSON.stringify(stored.values)}</span>
            </p>
          )}
          <HonestScope
            items={[
              'The committee threshold-decrypted ONE ciphertext: the network multiplied the two encrypted vectors under the level-0 ceremony key; neither vector was ever opened.',
              'Cross-term mask hiding ratio is 2¹⁰ (DEMO), not statistical.',
            ]}
          />
        </div>
        <div className="card col" style={{ gap: 10 }}>
          <div className="mono muted">Opened raw coefficients (64 × 4 decimals)</div>
          <details>
            <summary>show all</summary>
            <table className="ledger" data-testid="opened-table" style={{ marginTop: 12 }}>
              <thead>
                <tr>
                  <th>coefficient</th>
                  <th>opened raw value</th>
                </tr>
              </thead>
              <tbody>
                {res.opened.map((v, i) => (
                  <tr key={i}>
                    <td className="mono">
                      {i}
                      {i === 0 ? ' (−score)' : ' (masked cross term)'}
                    </td>
                    <td className="mono" data-testid={`opened-${i}`}>
                      {v.toFixed(4)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </details>
        </div>
      </div>
    </section>
  )
}
