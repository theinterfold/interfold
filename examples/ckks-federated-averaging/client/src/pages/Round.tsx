// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { getAddress } from 'viem'
import type { RoundDetail, SlotInfo } from '@ckks-fedavg/sdk'
import { D, squaredNorm, toFixedPointUpdate } from '@ckks-fedavg/sdk'
import { EncryptedInputCard, HonestScope, ProofSteps, ResultCard, RoundTimeline, SectionHeader, type ProofStep, type RoundPhase, e3Num, e3Short } from '@interfold/ckks-editorial'

import { api } from '../api'
import { loadStoredUpdate, useSubmitUpdate } from '../hooks/useSubmitUpdate'
import { useWallet } from '../wallet'
import { DEMO_UPDATES } from './Rounds'

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
              update window {fmtTime(r.inputWindow[0])} → {fmtTime(r.inputWindow[1])}
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
            <div className="mono">ParamSet {r.paramSet} · N=512 · 3 limbs · Δ=2⁴⁰</div>
            <div className="mono" data-testid="round-params">
              d = {r.d} · ‖g‖² ≤ {r.normBound} (×2³² = {r.normBoundFixedPoint}) · min clients = {r.minClients}
            </div>
            <div className="cap">
              committee key {r.publicKeyAvailable ? 'published' : 'DKG + level-0 relin ceremony in progress'} · Σ nᵢ·gᵢ computed on ciphertexts (1 ct×ct per client)
            </div>
          </div>
          <div className="card col" style={{ gap: 10 }}>
            <div className="mono muted">Registered clients (slot order; addresses only)</div>
            <table className="ledger">
              <tbody>
                {r.clients.map((a, i) => (
                  <tr key={a}>
                    <td className="mono">{i}</td>
                    <td className="mono">{a}</td>
                    <td>
                      {r.updates.some((u) => getAddress(u.publisher) === getAddress(a)) ? (
                        <span className="tag live">submitted</span>
                      ) : (
                        <span className="muted">—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <SubmitPanel round={r} />

      <section className="pad-section">
        <SectionHeader num="03" kicker="LEDGER" title="Accepted updates" meta={`${r.updates.length} verified on-chain / min ${r.minClients}`} />
        <table className="ledger" style={{ marginTop: 20 }}>
          <thead>
            <tr>
              <th>slot</th>
              <th>client</th>
              <th>tx</th>
              <th>m_commitment (grad / count)</th>
              <th>cts</th>
            </tr>
          </thead>
          <tbody>
            {r.updates.map((b) => (
              <tr key={b.transactionHash} data-testid="update-row">
                <td className="mono">{b.index}</td>
                <td className="mono">{b.publisher}</td>
                <td className="mono">{b.transactionHash.slice(0, 14)}…</td>
                <td className="mono">
                  {b.mCommitmentGrad.slice(0, 10)}… / {b.mCommitmentCount.slice(0, 10)}…
                </td>
                <td>{b.ciphertextAvailable ? <span className="tag live">verified on-chain</span> : <span className="tag closed">missing</span>}</td>
              </tr>
            ))}
            {r.updates.length === 0 && (
              <tr>
                <td colSpan={5} className="muted">
                  none yet
                </td>
              </tr>
            )}
          </tbody>
        </table>
        {(r.status === 'active' || r.status === 'evaluating') && (
          <div className="row" style={{ marginTop: 16, gap: 12 }}>
            <button
              type="button"
              className="btn ghost"
              data-testid="evaluate"
              disabled={evaluate.isPending || r.updates.length < r.minClients}
              onClick={() => evaluate.mutate()}
            >
              {evaluate.isPending ? 'Evaluating…' : 'Evaluate now (admin)'}
            </button>
            {r.updates.length < r.minClients && (
              <span className="muted">
                needs {r.minClients - r.updates.length} more update(s) — the server refuses to evaluate below the public minimum
              </span>
            )}
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

const SubmitPanel = ({ round }: { round: RoundDetail }) => {
  const { address } = useWallet()
  const { state, submit } = useSubmitUpdate(round.e3Id, round.programAddress)
  const [slot, setSlot] = useState<SlotInfo | null>(null)
  const registered = address ? round.clients.some((a) => getAddress(a) === getAddress(address)) : false
  const alreadySubmitted = address ? round.updates.some((b) => getAddress(b.publisher) === getAddress(address)) : false
  const demo = DEMO_UPDATES[slot?.index ?? 0] ?? DEMO_UPDATES[0]
  const [updateText, setUpdateText] = useState(JSON.stringify(demo.update))
  const [count, setCount] = useState(demo.count)
  const [boundOverride, setBoundOverride] = useState('')
  const canSubmit = round.status === 'active' && round.publicKeyAvailable && registered && !state.running

  useEffect(() => {
    setSlot(null)
    if (!address || !registered) return
    api
      .slot(round.e3Id, address)
      .then((s) => {
        setSlot(s)
        const d = DEMO_UPDATES[s.index] ?? DEMO_UPDATES[0]
        setUpdateText(JSON.stringify(d.update))
        setCount(d.count)
      })
      .catch(() => setSlot(null))
  }, [address, registered, round.e3Id])

  let update: number[] | null = null
  let parseError: string | null = null
  try {
    update = JSON.parse(updateText) as number[]
    if (!Array.isArray(update) || update.length !== D) parseError = `update must be an array of ${D} numbers`
  } catch (e) {
    parseError = (e as Error).message
  }
  const localNorm = update && !parseError ? squaredNorm(toFixedPointUpdate(update)) : null
  const overBound = localNorm !== null && localNorm > round.normBound

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
              Connect a wallet to submit. Your model update and your dataset size are encrypted and proven in this browser and sent from your
              own key — the server never sees them.
            </p>
          )}
          {address && !registered && <p className="error">{address} is not a registered client of this round</p>}
          {address && registered && slot && (
            <div className="card col" style={{ gap: 8 }}>
              <div className="mono muted">Your registered slot</div>
              <div>
                slot <b data-testid="my-index">{slot.index}</b> for <span className="mono">{address}</span> · round bound ‖g‖² ≤ {slot.normBound}
              </div>
              {alreadySubmitted && <span className="tag">you already submitted in this round</span>}
            </div>
          )}
          <div className="field">
            <label htmlFor="update">model update g (d = {D}, entries in [−1, 1])</label>
            <input id="update" data-testid="update" type="text" className="mono" value={updateText} onChange={(e) => setUpdateText(e.target.value)} />
          </div>
          <div className="row" style={{ gap: 16, alignItems: 'flex-end', flexWrap: 'wrap' }}>
            <div className="field" style={{ maxWidth: 200 }}>
              <label htmlFor="count">private sample count nᵢ (1 ≤ n &lt; 1024)</label>
              <input id="count" data-testid="count" type="number" min={1} max={1023} value={count} onChange={(e) => setCount(Number(e.target.value))} />
            </div>
            <span className="mono muted" data-testid="my-norm">
              {parseError ?? `local ‖g‖² = ${localNorm?.toFixed(6)}`}
              {overBound && <span className="error" style={{ marginLeft: 8 }}>over the round bound — the circuit will reject this</span>}
            </span>
          </div>
          <div className="row" style={{ gap: 12 }}>
            <button
              type="button"
              className="btn lg"
              data-testid="submit-update"
              disabled={!canSubmit || !!parseError}
              onClick={() => update && submit(update, count, boundOverride.trim() ? Number(boundOverride) : undefined).catch(() => {})}
            >
              {state.running ? 'Proving…' : 'Encrypt update + count, prove 5 legs & submit →'}
            </button>
            {round.status !== 'active' && <span className="muted">updates are {round.status === 'requested' ? 'not open yet (DKG + ceremony running)' : 'closed'}</span>}
          </div>
          <details>
            <summary>dev: prove against a DIFFERENT norm bound (the contract must reject it: WrongNormBound)</summary>
            <input data-testid="bound-override" type="text" style={{ width: '100%', marginTop: 8 }} placeholder="e.g. 4.0" value={boundOverride} onChange={(e) => setBoundOverride(e.target.value)} />
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
                title="update ciphertext · gradient_block(g)"
                seed={Number(BigInt(state.submission.uCommitmentG) % 100000n)}
                legs={['Greco ct0', 'Greco ct1', 'fedavg validity']}
                bytes={(state.submission.ciphertextG.length - 2) / 2}
              >
                <div className="mono-sm muted">‖g‖² {state.submission.squaredNorm.toFixed(6)} · fixed-point ×2¹⁶ [{state.submission.fixedPointUpdate.join(', ')}]</div>
              </EncryptedInputCard>
              <EncryptedInputCard
                title="count ciphertext · constant(n)"
                seed={Number(BigInt(state.submission.uCommitmentC) % 100000n)}
                legs={['Greco ct0', 'Greco ct1']}
                bytes={(state.submission.ciphertextC.length - 2) / 2}
              >
                <div className="mono-sm muted">private sample count n = {state.submission.count} (kept in this browser)</div>
              </EncryptedInputCard>
              <details>
                <summary>proof details</summary>
                <div className="mono-sm">slot {state.submission.index} · ‖g‖² {state.submission.squaredNorm.toFixed(6)} · n = {state.submission.count} (kept in this browser)</div>
                <div className="mono-sm">fixed-point update ×2¹⁶ [{state.submission.fixedPointUpdate.join(', ')}]</div>
                <div className="mono-sm">u_commitment grad {state.submission.uCommitmentG} · count {state.submission.uCommitmentC}</div>
                <div className="mono-sm">m_commitment grad {state.submission.mCommitmentG} · count {state.submission.mCommitmentC}</div>
                <div className="mono-sm">ciphertexts {(state.submission.ciphertextG.length - 2) / 2} + {(state.submission.ciphertextC.length - 2) / 2} bytes</div>
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
  const mine = address ? round.updates.find((b) => getAddress(b.publisher) === getAddress(address)) : undefined
  const stored = address ? loadStoredUpdate(round.e3Id, address) : null
  return (
    <section className="pad-section">
      <SectionHeader num="04" kicker="OPENED" title="One ciphertext, threshold-decrypted" meta="Σᵢ nᵢ·gᵢ at j+1 · Σᵢ nᵢ at d+1" />
      <div className="grid-2" style={{ marginTop: 24 }}>
        <div className="col" style={{ gap: 16 }}>
          <ResultCard
            testId="total-count-card"
            label="Total samples — the network weighted by counts it never saw"
            value={<span data-testid="total-count">{Math.round(res.totalCount)}</span>}
            unit="Σᵢ nᵢ"
            caption={
              <>
                coefficient 0 (should be ≈ 0): <span className="mono">{res.opened[0]?.toFixed(4)}</span> · your contribution weight{' '}
                <span className="mono">
                  {stored && mine ? `${stored.count} / ${Math.round(res.totalCount)} = ${(stored.count / res.totalCount).toFixed(4)}` : '—'}
                </span>
              </>
            }
            reveals="The sample-weighted SUM of the updates and the total sample count — the aggregate, computed by the network on ciphertexts (each client's encrypted count × its encrypted update under the level-0 ceremony key, then summed)."
            hides="Any individual update or count. No client's contribution is ever opened — only these aggregates are public."
          />
          {address && !mine && <p className="muted">you did not submit in this round</p>}
          <HonestScope
            items={[
              'The committee threshold-decrypted ONE ciphertext: coefficient j+1 is Σᵢ nᵢ·g_{i,j} and coefficient d+1 is Σᵢ nᵢ. The weighted mean is their ratio.',
              'The aggregate is public; with few clients this is the usual FedAvg leakage — the server enforces the round’s minimum client count before evaluating.',
            ]}
          />
        </div>
        <div className="card col" style={{ gap: 10 }}>
          <div className="mono muted">Sample-weighted mean update ḡ = opened[1..=d] / opened[d+1]</div>
          <table className="ledger" data-testid="mean-table">
            <thead>
              <tr>
                <th>j</th>
                <th>Σ nᵢ·g_ij (opened)</th>
                <th>weighted mean ḡ_j</th>
                {stored && <th>your g_j (local)</th>}
              </tr>
            </thead>
            <tbody>
              {res.mean.map((v, j) => (
                <tr key={j}>
                  <td className="mono">{j}</td>
                  <td className="mono muted">{res.opened[j + 1]?.toFixed(4)}</td>
                  <td className="mono" data-testid={`mean-${j}`}>
                    {v.toFixed(6)}
                  </td>
                  {stored && <td className="mono muted">{stored.update[j]}</td>}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  )
}
