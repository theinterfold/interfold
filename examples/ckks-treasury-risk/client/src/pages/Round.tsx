// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { getAddress } from 'viem'
import type { RoundDetail, SlotResponse } from '@ckks-treasury/sdk'
import { ASSETS, MIN_DAOS } from '@ckks-treasury/sdk'
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

/** Demo books (raw, cap 100): slot 0 = the contract fixture's exposures ×100; the others are plausible DAO books. */
export const DEMO_CAP = 100
export const DEMO_BOOKS: number[][] = [
  [30, 10, 45, 15],
  [20, 10, 0, 10],
  [5, 40, 25, 30],
]

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
            <div className="mono">
              ParamSet {r.paramSet} · N=512 · 3 limbs · Δ=2⁴⁰ · assets = {r.assets}
            </div>
            <div className="mono">
              public weights <span data-testid="round-weights">[{r.weights.join(', ')}]</span>
            </div>
            <div className="mono-sm muted">registered ×2¹⁶: [{r.weightsFixed.join(', ')}]</div>
            <div className="cap">
              committee key {r.publicKeyAvailable ? 'published' : 'DKG + level-0 relin ceremony in progress'} · risk computed on the summed encrypted
              books (1 ct×ct)
            </div>
          </div>
          <div className="card col" style={{ gap: 10 }}>
            <div className="mono muted">Registered DAOs (slot = position)</div>
            <table className="ledger">
              <tbody>
                {r.daos.map((a, i) => (
                  <tr key={a}>
                    <td className="mono">{i}</td>
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
        <SectionHeader num="03" kicker="LEDGER" title="Accepted submissions" meta={`${r.submissions.length} / ${r.daos.length} DAOs · min ${MIN_DAOS}`} />
        <table className="ledger" style={{ marginTop: 20 }}>
          <thead>
            <tr>
              <th>slot</th>
              <th>DAO</th>
              <th>tx</th>
              <th>m_commitment (fwd / rev / mask)</th>
              <th>cts</th>
            </tr>
          </thead>
          <tbody>
            {r.submissions.map((b) => (
              <tr key={b.transactionHash} data-testid="submission-row">
                <td className="mono">{b.index}</td>
                <td className="mono">{b.publisher}</td>
                <td className="mono">{b.transactionHash.slice(0, 14)}…</td>
                <td className="mono">
                  {b.mCommitmentFwd.slice(0, 10)}… / {b.mCommitmentRev.slice(0, 10)}… / {b.mCommitmentMask.slice(0, 10)}…
                </td>
                <td>{b.ciphertextAvailable ? <span className="tag live">verified on-chain</span> : <span className="tag closed">missing</span>}</td>
              </tr>
            ))}
            {r.submissions.length === 0 && (
              <tr>
                <td colSpan={5} className="muted">
                  none yet
                </td>
              </tr>
            )}
          </tbody>
        </table>
        {(r.status === 'active' || r.status === 'evaluating') && r.submissions.length >= MIN_DAOS && (
          <div className="row" style={{ marginTop: 16, gap: 12 }}>
            <button type="button" className="btn ghost" data-testid="evaluate" disabled={evaluate.isPending} onClick={() => evaluate.mutate()}>
              {evaluate.isPending ? 'Evaluating…' : 'Evaluate now (admin)'}
            </button>
            {evaluate.isError && <span className="error">{(evaluate.error as Error).message}</span>}
          </div>
        )}
        {r.status === 'active' && r.submissions.length < r.daos.length && (
          <p className="muted" style={{ marginTop: 16 }}>
            the server evaluates automatically as soon as every registered DAO has submitted, or when the window closes with at least {MIN_DAOS}
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
  const { state, submit } = useApply(round.e3Id, round.programAddress, round.weights)
  const [slot, setSlot] = useState<SlotResponse | null>(null)
  const registeredIndex = address ? round.daos.findIndex((a) => getAddress(a) === getAddress(address)) : -1
  const registered = registeredIndex >= 0
  const demoBook = (i: number) => DEMO_BOOKS[((i % DEMO_BOOKS.length) + DEMO_BOOKS.length) % DEMO_BOOKS.length]
  const [raw, setRaw] = useState<string[]>(demoBook(0).map(String))
  const [cap, setCap] = useState(DEMO_CAP)
  const [wrongWeights, setWrongWeights] = useState(false)
  const alreadySubmitted = address ? round.submissions.some((b) => getAddress(b.publisher) === getAddress(address)) : false
  const canSubmit = round.status === 'active' && round.publicKeyAvailable && registered && !alreadySubmitted && !state.running

  useEffect(() => {
    setSlot(null)
    if (!address || !registered) return
    api.slot(round.e3Id, address).then(setSlot).catch(() => setSlot(null))
    setRaw(demoBook(registeredIndex).map(String))
  }, [address, registered, registeredIndex, round.e3Id])

  const parsedRaw = (): number[] => {
    const v = raw.map(Number)
    if (v.length !== ASSETS || v.some((x) => !Number.isFinite(x))) throw new Error(`the exposure vector must have exactly ${ASSETS} numeric entries`)
    return v
  }

  const steps: ProofStep[] = state.steps.map((s) => ({
    label: s.label,
    state: s.status === 'running' ? 'running' : s.status === 'done' ? 'done' : 'failed',
    detail: s.ms !== undefined ? `${Math.round(s.ms)} ms` : undefined,
  }))

  return (
    <section className="pad-section">
      <SectionHeader num="02" kicker="SUBMIT" title="Encrypt, prove, submit — from this browser" meta="3 ciphertexts · 7 UltraHonk legs" />
      <div className="grid-2" style={{ marginTop: 24 }}>
        <div className="col" style={{ gap: 16 }}>
          {!address && (
            <p className="muted">
              Connect a wallet to submit. Your exposures and your cross-term mask are encrypted and proven in this browser and sent from your own
              key.
            </p>
          )}
          {address && !registered && <p className="error">{address} is not a registered DAO of this round</p>}
          {address && registered && slot && (
            <div className="card col" style={{ gap: 8 }}>
              <div className="mono muted">Your registered slot</div>
              <div>
                DAO slot <b data-testid="my-index">{slot.index}</b> · address <span className="mono">{address}</span>
              </div>
              {alreadySubmitted && <span className="tag">you already submitted in this round</span>}
            </div>
          )}
          <div className="row" style={{ gap: 12, alignItems: 'flex-end' }}>
            {raw.map((v, a) => (
              <div key={a} className="field" style={{ maxWidth: 110 }}>
                <label htmlFor={`exposure-${a}`}>asset {a}</label>
                <input
                  id={`exposure-${a}`}
                  data-testid={`exposure-${a}`}
                  type="number"
                  min={0}
                  value={v}
                  onChange={(e) => setRaw(raw.map((x, i) => (i === a ? e.target.value : x)))}
                />
              </div>
            ))}
            <div className="field" style={{ maxWidth: 110 }}>
              <label htmlFor="cap">cap</label>
              <input id="cap" data-testid="cap" type="number" value={cap} onChange={(e) => setCap(Number(e.target.value))} />
            </div>
          </div>
          <p className="muted" style={{ margin: 0 }}>
            raw exposures are divided by the cap: every entry must land in [0, 1] (the circuit rejects anything else)
          </p>
          <div className="row" style={{ gap: 12 }}>
            <button
              type="button"
              className="btn lg"
              data-testid="submit"
              disabled={!canSubmit}
              onClick={() => {
                try {
                  submit(parsedRaw(), cap, wrongWeights ? round.weights.map((w, a) => (a === 1 ? w + 0.01 : w)) : undefined).catch(() => {})
                } catch (e) {
                  alert((e as Error).message)
                }
              }}
            >
              {state.running ? 'Proving…' : 'Encrypt forward + reversed(w∘x) + mask, prove 7 legs & submit →'}
            </button>
            {round.status !== 'active' && <span className="muted">submissions are {round.status === 'requested' ? 'not open yet (DKG + ceremony running)' : 'closed'}</span>}
          </div>
          <details>
            <summary>dev: prove under the WRONG weights (the contract must reject it with WrongWeights)</summary>
            <label className="row" style={{ gap: 8, marginTop: 8 }}>
              <input data-testid="wrong-weights" type="checkbox" checked={wrongWeights} onChange={(e) => setWrongWeights(e.target.checked)} /> nudge w_1 by +0.01 before proving
            </label>
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
              <EncryptedInputCard title="forward(x) ciphertext" seed={Number(BigInt(state.submission.uCommitmentFwd) % 100000n)} legs={['Greco ct0', 'Greco ct1', 'treasury validity']} bytes={(state.submission.ciphertextFwd.length - 2) / 2}>
                <div className="mono-sm muted">fixed-point exposures (×2¹⁶, kept in this browser) {JSON.stringify(state.submission.fixedPoint)}</div>
              </EncryptedInputCard>
              <EncryptedInputCard title="reversed(w∘x) ciphertext" seed={Number(BigInt(state.submission.uCommitmentRev) % 100000n)} legs={['Greco ct0', 'Greco ct1']} bytes={(state.submission.ciphertextRev.length - 2) / 2}>
                <div className="mono-sm muted">weights (×2¹⁶, public) {JSON.stringify(state.submission.weightsFixed)}</div>
              </EncryptedInputCard>
              <EncryptedInputCard title="mask(m) ciphertext" seed={Number(BigInt(state.submission.uCommitmentMask) % 100000n)} legs={['Greco ct0', 'Greco ct1']} bytes={(state.submission.ciphertextMask.length - 2) / 2}>
                <div className="mono-sm muted">128 uniform integers in [0, 1024) on coefficients 1…128 — kept in this browser</div>
              </EncryptedInputCard>
              <details>
                <summary>proof details</summary>
                <div className="mono-sm">slot {state.submission.index}</div>
                <div className="mono-sm">
                  u_commitment fwd {state.submission.uCommitmentFwd} · rev {state.submission.uCommitmentRev} · mask {state.submission.uCommitmentMask}
                </div>
                <div className="mono-sm">
                  m_commitment fwd {state.submission.mCommitmentFwd} · rev {state.submission.mCommitmentRev} · mask {state.submission.mCommitmentMask}
                </div>
                <div className="mono-sm">
                  ciphertexts {(state.submission.ciphertextFwd.length - 2) / 2} + {(state.submission.ciphertextRev.length - 2) / 2} +{' '}
                  {(state.submission.ciphertextMask.length - 2) / 2} bytes
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
  const ownRisk = stored ? stored.exposures.reduce((acc, x, a) => acc + stored.weights[a] * x * x, 0) : null
  return (
    <section className="pad-section">
      <SectionHeader num="04" kicker="OPENED" title="One ciphertext, threshold-decrypted" meta="coefficient 0 = −risk" />
      <div className="grid-2" style={{ marginTop: 24 }}>
        <div className="col" style={{ gap: 16 }}>
          <ResultCard
            testId="risk-card"
            label="Weighted concentration risk of the combined book — the same number for every DAO"
            value={<span data-testid="risk">{res.risk.toFixed(4)}</span>}
            caption={
              <>
                −opened[0] under public w = <span className="mono">[{round.weights.join(', ')}]</span> · {round.submissions.length} DAOs
                {stored && ownRisk !== null && (
                  <>
                    {' '}
                    · your own single-book risk (slot {stored.index}, kept in this browser) would be <span className="mono">{ownRisk.toFixed(4)}</span>
                  </>
                )}
              </>
            }
            reveals="This one scalar Σₐ wₐ(Σᵢ xᵢ,ₐ)²: the network summed every DAO's forward(xᵢ) and reversed(w∘xᵢ), multiplied the two sums under the ceremony key, added every mask, and the app negated the tᴺ ≡ −1 wrap."
            hides="Any DAO's book, the aggregate book Σᵢ xᵢ (the per-asset sums never leave encryption), and coefficients 1… of the output — cross terms hidden by every DAO's uniform mask."
          />
          {stored && (
            <div className="card col" style={{ gap: 8 }}>
              <div className="mono muted">Your own book (kept in this browser, slot {stored.index})</div>
              <div className="mono">{JSON.stringify(stored.exposures)}</div>
            </div>
          )}
          <HonestScope
            items={[
              'Coefficient 0 is −Σₐ wₐ(Σᵢ xᵢ,ₐ)² of the combined book, computed on the summed ciphertexts (one ct×ct product under the level-0 ceremony key).',
              'Coefficients 1… are cross terms Σ w_b Xₐ X_b hidden by every DAO’s uniform mask (demo hiding ratio 2¹⁰); without the masks, never published, they say nothing.',
            ]}
          />
        </div>
        <div className="card col" style={{ gap: 10 }}>
          <div className="mono muted">Raw opened coefficients (64 × 4 decimals)</div>
          <details>
            <summary>show all 64</summary>
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
                      {i === 0 ? ' (−risk)' : ' (masked cross term)'}
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
