// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { getAddress } from 'viem'
import type { RoundDetail, FeatureProof, Model } from '@ckks-credit/sdk'
import { creditLogit, recoverScore, sigmoidCubic, toFixedPoint } from '@ckks-credit/sdk'
import { EncryptedInputCard, HonestScope, ProofSteps, ResultCard, RoundTimeline, SectionHeader, type ProofStep, type RoundPhase, e3Num, e3Short } from '@interfold/ckks-editorial'

import { api } from '../api'
import { loadMask, useApply } from '../hooks/useApply'
import { useWallet } from '../wallet'

/** Map the server's round status onto the editorial timeline. */
const phaseOf = (r: RoundDetail): RoundPhase => {
  if (r.status === 'failed') return 'failed'
  if (r.status === 'finished') return 'published'
  if (r.status === 'evaluating') return 'evaluating'
  if (r.status === 'active') return r.publicKeyAvailable ? 'open' : 'ceremony'
  return 'keygen'
}

const fmtTime = (s: number) => new Date(s * 1000).toLocaleTimeString()

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
            <div className="mono">ParamSet {r.paramSet} · N=512 · 5 limbs · Δ=2⁴⁰</div>
            <div className="mono">issuer root {r.issuerRoot ?? '—'}</div>
            <div className="cap">
              committee key {r.publicKeyAvailable ? 'published' : 'DKG + 2-level relin ceremony in progress'} · σ(z) computed on the encrypted logit (2 ct×ct)
            </div>
          </div>
          <div className="card col" style={{ gap: 10 }}>
            <div className="mono muted">Public model</div>
            <div className="mono" data-testid="model">
              w = [{r.model.weights.join(', ')}] · b = {r.model.bias} · cap = {r.cap}
            </div>
            {r.fixedPointModel && (
              <div className="mono-sm muted">
                registered ×2¹⁶: [{r.fixedPointModel.weights.join(', ')}] · {r.fixedPointModel.bias}
              </div>
            )}
            <div className="mono muted" style={{ marginTop: 6 }}>
              Registered applicants (slot order; addresses only)
            </div>
            <table className="ledger">
              <tbody>
                {r.applicantAddresses.map((a, i) => (
                  <tr key={a}>
                    <td className="mono">{i}</td>
                    <td className="mono">{a}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <ApplyPanel round={r} />

      <section className="pad-section">
        <SectionHeader num="03" kicker="LEDGER" title="Accepted applications" meta={`${r.applications.length} verified on-chain`} />
        <table className="ledger" style={{ marginTop: 20 }}>
          <thead>
            <tr>
              <th>slot</th>
              <th>applicant</th>
              <th>tx</th>
              <th>m_commitment (z / m)</th>
              <th>status</th>
            </tr>
          </thead>
          <tbody>
            {r.applications.map((b) => (
              <tr key={b.transactionHash} data-testid="application-row">
                <td className="mono">{b.index}</td>
                <td className="mono">{b.publisher}</td>
                <td className="mono">{b.transactionHash.slice(0, 14)}…</td>
                <td className="mono">
                  {b.mCommitmentZ.slice(0, 10)}… / {b.mCommitmentM.slice(0, 10)}…
                </td>
                <td>{b.ciphertextAvailable ? <span className="tag live">verified on-chain</span> : <span className="tag closed">missing</span>}</td>
              </tr>
            ))}
            {r.applications.length === 0 && (
              <tr>
                <td colSpan={5} className="muted">
                  none yet
                </td>
              </tr>
            )}
          </tbody>
        </table>
        {(r.status === 'active' || r.status === 'evaluating') && r.applications.length >= 1 && (
          <div className="row" style={{ marginTop: 16, gap: 12 }}>
            <button type="button" className="btn ghost" data-testid="evaluate" disabled={evaluate.isPending} onClick={() => evaluate.mutate()}>
              {evaluate.isPending ? 'Evaluating…' : 'Evaluate now (admin)'}
            </button>
            {evaluate.isError && <span className="error">{(evaluate.error as Error).message}</span>}
          </div>
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

const ApplyPanel = ({ round }: { round: RoundDetail }) => {
  const { address } = useWallet()
  const { state, submit } = useApply(round.e3Id, round.programAddress, round.model)
  const [proof, setProof] = useState<FeatureProof | null>(null)
  const [override, setOverride] = useState('')
  const [modelOverride, setModelOverride] = useState('')
  const inSnapshot = address ? round.applicantAddresses.some((a) => getAddress(a) === getAddress(address)) : false
  const alreadyApplied = address ? round.applications.some((b) => getAddress(b.publisher) === getAddress(address)) : false
  const canApply = round.status === 'active' && round.publicKeyAvailable && inSnapshot && !state.running

  useEffect(() => {
    setProof(null)
    if (!address || !inSnapshot) return
    api.featureProof(round.e3Id, address).then(setProof).catch(() => setProof(null))
  }, [address, inSnapshot, round.e3Id])

  const overrideFeatures = override.trim() ? (JSON.parse(override) as number[]) : undefined
  const overrideModel = modelOverride.trim() ? (JSON.parse(modelOverride) as Model) : undefined
  const localLogit = proof ? creditLogit(toFixedPoint(round.model), proof.features, proof.cap) : null

  const steps: ProofStep[] = state.steps.map((s) => ({
    label: s.label,
    state: s.status === 'running' ? 'running' : s.status === 'done' ? 'done' : 'failed',
    detail: s.ms !== undefined ? `${Math.round(s.ms)} ms` : undefined,
  }))

  return (
    <section className="pad-section">
      <SectionHeader num="02" kicker="APPLY" title="Encrypt, prove, submit — from this browser" meta="5 UltraHonk legs" />
      <div className="grid-2" style={{ marginTop: 24 }}>
        <div className="col" style={{ gap: 16 }}>
          {!address && (
            <p className="muted">
              Connect a wallet to apply. The model's logit over your attested features and your output mask are encrypted and proven here and sent
              from your own key.
            </p>
          )}
          {address && !inSnapshot && <p className="error">{address} is not in this round's issuer snapshot</p>}
          {address && inSnapshot && proof && (
            <div className="card col" style={{ gap: 8 }}>
              <div className="mono muted">Your attested leaf</div>
              <div>
                slot <b data-testid="my-index">{proof.index}</b> · features{' '}
                <b className="mono hex" data-testid="my-features">
                  {JSON.stringify(proof.features)}
                </b>{' '}
                over cap {proof.cap}
              </div>
              <div>
                local logit z ={' '}
                <span className="mono hex" data-testid="my-logit">
                  {localLogit?.toFixed(6)}
                </span>{' '}
                · σ(z) = {localLogit !== null ? sigmoidCubic(localLogit).toFixed(6) : '—'}
              </div>
              {alreadyApplied && <span className="tag">you already applied in this round</span>}
            </div>
          )}
          <div className="row" style={{ gap: 12 }}>
            <button type="button" className="btn lg" data-testid="apply-submit" disabled={!canApply} onClick={() => submit(overrideFeatures, overrideModel).catch(() => {})}>
              {state.running ? 'Proving…' : 'Encrypt logit + mask, prove 5 legs & apply →'}
            </button>
            {round.status !== 'active' && <span className="muted">applications are {round.status === 'requested' ? 'not open yet (DKG running)' : 'closed'}</span>}
          </div>
          <details>
            <summary>dev: submit a DIFFERENT feature vector (the circuit must reject it)</summary>
            <input data-testid="feature-override" type="text" style={{ width: '100%', marginTop: 8 }} placeholder="e.g. [520,130,350,1001,0,1,777,42]" value={override} onChange={(e) => setOverride(e.target.value)} />
          </details>
          <details>
            <summary>dev: apply under a DIFFERENT model (the contract must reject it)</summary>
            <input data-testid="model-override" type="text" style={{ width: '100%', marginTop: 8 }} placeholder='e.g. {"weights":[1,1,1,1,1,1,1,1],"bias":0}' value={modelOverride} onChange={(e) => setModelOverride(e.target.value)} />
          </details>
          {state.error && (
            <p className="error" data-testid="apply-error">
              {state.error}
            </p>
          )}
          {state.txHash && (
            <p>
              <span className="tag live" data-testid="apply-verified">
                verified on-chain
              </span>{' '}
              tx <span className="mono hex">{state.txHash}</span> · gas{' '}
              <span className="mono hex" data-testid="apply-gas">
                {state.gasUsed?.toString()}
              </span>
            </p>
          )}
        </div>
        <div className="col" style={{ gap: 16 }}>
          {steps.length > 0 && <ProofSteps steps={steps} testId="apply-steps" />}
          {state.submission && (
            <>
              <EncryptedInputCard title="logit ciphertext" seed={Number(BigInt(state.submission.uCommitmentZ) % 100000n)} legs={['Greco ct0', 'Greco ct1', 'credit validity']} bytes={(state.submission.ciphertextZ.length - 2) / 2} />
              <EncryptedInputCard title="mask ciphertext" seed={Number(BigInt(state.submission.uCommitmentM) % 100000n)} legs={['Greco ct0', 'Greco ct1']} bytes={(state.submission.ciphertextM.length - 2) / 2}>
                <div className="mono-sm muted">output mask (kept in this browser) {state.submission.mask} / 1024 = {(state.submission.mask / 1024).toFixed(4)}</div>
              </EncryptedInputCard>
              <details>
                <summary>proof details</summary>
                <div className="mono-sm">slot {state.submission.index} · logit z {state.submission.logit}</div>
                <div className="mono-sm">u_commitment z {state.submission.uCommitmentZ} · m {state.submission.uCommitmentM}</div>
                <div className="mono-sm">m_commitment z {state.submission.mCommitmentZ} · m {state.submission.mCommitmentM}</div>
                <pre className="mono-sm hex" data-testid="apply-timings">
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
  const mine = address ? round.applications.find((b) => getAddress(b.publisher) === getAddress(address)) : undefined
  const stored = address ? loadMask(round.e3Id, address) : null
  const recovered = mine && stored ? recoverScore(res.opened, mine.index, stored.mask) : null
  const expected = stored ? sigmoidCubic(stored.logit) : null
  return (
    <section className="pad-section">
      <SectionHeader num="04" kicker="OPENED" title="One ciphertext, threshold-decrypted" meta="σ(zᵢ) + mᵢ per slot" />
      <div className="grid-2" style={{ marginTop: 24 }}>
        <div className="col" style={{ gap: 16 }}>
          {recovered && (
            <ResultCard
              testId="my-score-card"
              label="Your score — computed by the network; only you can read it"
              value={<span data-testid="my-score">{recovered.probability.toFixed(3)}</span>}
              caption={
                <>
                  opened <span data-testid="my-opened">{recovered.opened.toFixed(4)}</span> − m {recovered.mask.toFixed(4)} = σ(z) ={' '}
                  <span className="mono hex" data-testid="my-probability">
                    {recovered.probability.toFixed(6)}
                  </span>
                  {expected !== null && (
                    <>
                      {' '}
                      · local σ_cubic(z) = <span data-testid="my-expected">{expected.toFixed(6)}</span>
                    </>
                  )}
                </>
              }
              reveals="Your probability σ(z) — to you alone, after subtracting the mask this browser kept."
              hides="Your features, your logit, your mask, and every other applicant's score. An empty slot opens as 0.5."
            />
          )}
          {address && mine && !stored && <p className="error">no mask stored in this browser for round {e3Short(round.e3Id)} — the score cannot be recovered here</p>}
          {address && !mine && <p className="muted">you did not apply in this round</p>}
          <HonestScope
            items={[
              'Slot i is applicant i\u2019s masked probability σ(zᵢ) + mᵢ, computed on the encrypted logit (two ct×ct products under the ceremony keys).',
              'Without mᵢ, never published, these raw values say nothing.',
            ]}
          />
        </div>
        <div className="card col" style={{ gap: 10 }}>
          <div className="mono muted">Opened raw values</div>
          <table className="ledger" data-testid="opened-table">
            <thead>
              <tr>
                <th>slot</th>
                <th>applicant</th>
                <th>σ + m</th>
              </tr>
            </thead>
            <tbody>
              {res.opened.map((v, i) => (
                <tr key={i}>
                  <td className="mono">{i}</td>
                  <td className="mono">
                    {round.applicantAddresses[i] ?? '?'}
                    {round.applications.some((b) => b.index === i) ? '' : ' (did not apply)'}
                  </td>
                  <td className="mono" data-testid={`opened-${i}`}>
                    {v.toFixed(4)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  )
}
