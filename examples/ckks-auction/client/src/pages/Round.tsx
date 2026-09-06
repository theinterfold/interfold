// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useParams } from 'react-router-dom'
import { getAddress } from 'viem'
import type { RoundDetail } from '@ckks-auction/sdk'
import { EncryptedInputCard, HonestScope, ProofSteps, ResultCard, RoundTimeline, SectionHeader, type ProofStep, type RoundPhase, e3Num, e3Short } from '@interfold/ckks-editorial'

import { api } from '../api'
import { useBid } from '../hooks/useBid'
import { useWallet } from '../wallet'

/** Map the server's round status onto the editorial timeline (this app has a hybrid relin ceremony after DKG). */
const phaseOf = (r: RoundDetail): RoundPhase => {
  if (r.status === 'failed') return 'failed'
  if (r.status === 'finished') return 'published'
  if (r.status === 'evaluating') return 'evaluating'
  if (r.status === 'active') {
    if (!r.publicKeyAvailable) return 'keygen'
    return r.ceremonyKeys >= r.ceremonyKeysExpected ? 'open' : 'ceremony'
  }
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
  const ceremonyDone = r.ceremonyKeys >= r.ceremonyKeysExpected
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
              bidding window {fmtTime(r.inputWindow[0])} → {fmtTime(r.inputWindow[1])}
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
            <div className="mono">ParamSet 2 · N=512 · 38 limbs · Δ=2⁴⁰ · depth 37</div>
            <div className="mono">balance root {r.balanceRoot ?? '—'}</div>
            <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
              <span className={`tag ${r.publicKeyAvailable ? 'live' : ''}`}>committee key {r.publicKeyAvailable ? 'published' : 'DKG in progress'}</span>
              <span className={`tag ${ceremonyDone ? 'live' : ''}`}>
                hybrid relin ceremony {r.ceremonyKeys}/{r.ceremonyKeysExpected} keys
              </span>
            </div>
            <div className="cap">
              one hybrid ceremony key serves all 24 multiplication levels · 12 cubic sign-extraction iterations on the packed i&lt;j differences
            </div>
          </div>
          <div className="card col" style={{ gap: 10 }}>
            <div className="mono muted">Balance snapshot</div>
            <div className="cap">Poseidon (address, balance) leaves under the round’s root; a bid must be ≤ the attested balance.</div>
            <table className="ledger">
              <thead>
                <tr>
                  <th>bidder</th>
                  <th>balance</th>
                </tr>
              </thead>
              <tbody>
                {r.snapshot.map((h) => (
                  <tr key={h.address}>
                    <td className="mono">{h.address}</td>
                    <td className="mono">{h.balance}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <BidPanel round={r} />

      <section className="pad-section">
        <SectionHeader num="03" kicker="LEDGER" title="Accepted bids" meta={`${r.bids.length} verified on-chain`} />
        <table className="ledger" style={{ marginTop: 20 }}>
          <thead>
            <tr>
              <th>#</th>
              <th>bidder</th>
              <th>tx</th>
              <th>u_commitment</th>
              <th>ct</th>
            </tr>
          </thead>
          <tbody>
            {r.bids.map((b) => (
              <tr key={b.transactionHash} data-testid="bid-row">
                <td className="mono">{b.index}</td>
                <td className="mono">{b.publisher}</td>
                <td className="mono">{b.transactionHash.slice(0, 14)}…</td>
                <td className="mono">{b.uCommitment.slice(0, 14)}…</td>
                <td>{b.ciphertextAvailable ? <span className="tag live">verified on-chain</span> : <span className="tag closed">missing</span>}</td>
              </tr>
            ))}
            {r.bids.length === 0 && (
              <tr>
                <td colSpan={5} className="muted">
                  none yet
                </td>
              </tr>
            )}
          </tbody>
        </table>
        {(r.status === 'active' || r.status === 'evaluating') && r.bids.length >= 2 && (
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

const BidPanel = ({ round }: { round: RoundDetail }) => {
  const { address } = useWallet()
  const { state, submit } = useBid(round.e3Id, round.programAddress)
  const [bid, setBid] = useState('')
  const mine = address ? round.snapshot.find((h) => getAddress(h.address) === getAddress(address)) : undefined
  const alreadyBid = address ? round.bids.some((b) => getAddress(b.publisher) === getAddress(address)) : false
  const canBid = round.status === 'active' && round.publicKeyAvailable && !!mine && !state.running

  const steps: ProofStep[] = state.steps.map((s) => ({
    label: s.label,
    state: s.status === 'running' ? 'running' : s.status === 'done' ? 'done' : 'failed',
    detail: s.ms !== undefined ? `${Math.round(s.ms)} ms` : undefined,
  }))

  return (
    <section className="pad-section">
      <SectionHeader num="02" kicker="BID" title="Encrypt, prove, submit — from this browser" meta="3 UltraHonk legs" />
      <div className="grid-2" style={{ marginTop: 24 }}>
        <div className="col" style={{ gap: 16 }}>
          {!address && <p className="muted">Connect a wallet to bid. Your bid is encrypted and proven in this browser and sent from your own key.</p>}
          {address && !mine && <p className="error">{address} is not in this round's balance snapshot</p>}
          {address && mine && (
            <div className="card col" style={{ gap: 8 }}>
              <div className="mono muted">Your attested leaf</div>
              <div>
                balance for <span className="mono">{address}</span>: <b data-testid="my-balance">{mine.balance}</b> — you can bid at most that.
              </div>
              {alreadyBid && <span className="tag">you already bid in this round</span>}
            </div>
          )}
          <div className="row" style={{ gap: 12, alignItems: 'flex-end' }}>
            <div className="field" style={{ maxWidth: 200 }}>
              <label htmlFor="bid">bid</label>
              <input id="bid" data-testid="bid-input" type="number" placeholder="bid" value={bid} onChange={(e) => setBid(e.target.value)} disabled={!canBid} />
            </div>
            <button type="button" className="btn lg" data-testid="bid-submit" disabled={!canBid || !bid} onClick={() => submit(Number(bid)).catch(() => {})}>
              {state.running ? 'Proving…' : 'Encrypt, prove 3 legs & submit →'}
            </button>
            {round.status !== 'active' && <span className="muted">bidding is {round.status === 'requested' ? 'not open yet (DKG running)' : 'closed'}</span>}
          </div>
          {state.error && (
            <p className="error" data-testid="bid-error">
              {state.error}
            </p>
          )}
          {state.txHash && (
            <p>
              <span className="tag live" data-testid="bid-verified">
                verified on-chain
              </span>{' '}
              tx <span className="mono hex">{state.txHash}</span> · gas{' '}
              <span className="mono hex" data-testid="bid-gas">
                {state.gasUsed?.toString()}
              </span>
            </p>
          )}
        </div>
        <div className="col" style={{ gap: 16 }}>
          {steps.length > 0 && <ProofSteps steps={steps} testId="bid-steps" />}
          {state.submission && (
            <>
              <EncryptedInputCard
                title="bid ciphertext"
                seed={Number(BigInt(state.submission.uCommitment) % 100000n)}
                legs={['Greco ct0', 'Greco ct1', 'auction validity']}
                bytes={(state.submission.ciphertext.length - 2) / 2}
              />
              <details>
                <summary>proof details</summary>
                <div className="mono-sm">u_commitment {state.submission.uCommitment}</div>
                <div className="mono-sm">m_commitment {state.submission.mCommitment}</div>
                <div className="mono-sm">ciphertext {(state.submission.ciphertext.length - 2) / 2} bytes</div>
                <pre className="mono-sm hex" data-testid="bid-timings">
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
  const res = round.results!
  return (
    <section className="pad-section">
      <SectionHeader num="04" kicker="OPENED" title="One ciphertext, threshold-decrypted" meta="±1 sign per i<j pair" />
      <div className="grid-2" style={{ marginTop: 24 }}>
        <div className="col" style={{ gap: 16 }}>
          <ResultCard
            testId="winner"
            label="Winner — ranked by the network on ciphertext"
            value={<>bidder #{res.winner}</>}
            caption={
              <>
                {res.winnerAddress && <span className="mono">{res.winnerAddress}</span>}
                {res.winnerAddress && ' · '}
                opened output:{' '}
                {res.binarized ? (
                  <span className="tag live" data-testid="binarized">
                    only saturated ±1 signs
                  </span>
                ) : (
                  <span className="tag closed">unsaturated slot(s) — a gap below ~2% of the bound</span>
                )}
                {' · '}wins per bidder {res.wins.join(' / ')}
              </>
            }
            reveals="Who won, and the full comparison order among bidders — every i<j pair as a saturated ±1 sign."
            hides="Every bid value and every gap between bids. Slots that would carry magnitude are binarised to exactly ±1 before opening."
          />
          <HonestScope
            items={[
              'Each opened slot is sign(bidᵢ − bidⱼ) after 12 cubic sign-extraction iterations (depth 37) under one hybrid ceremony key.',
              'Magnitudes are saturated: an unsaturated slot would mean a gap below ~2% of the bound, and the server flags it.',
            ]}
          />
        </div>
        <div className="card col" style={{ gap: 10 }}>
          <div className="mono muted">Binarized sign matrix</div>
          <table className="ledger" data-testid="sign-matrix">
            <thead>
              <tr>
                <th>pair (i, j)</th>
                <th>decrypted slot</th>
                <th>sign</th>
                <th>meaning</th>
              </tr>
            </thead>
            <tbody>
              {res.pairs.map(([a, b], p) => (
                <tr key={p}>
                  <td className="mono">
                    ({a}, {b})
                  </td>
                  <td className="mono">{res.values[p].toFixed(2)}</td>
                  <td className={`mono ${res.signs[p] > 0 ? 'accent' : 'warm'}`} style={{ fontWeight: 600 }}>
                    {res.signs[p] > 0 ? '+1' : '−1'}
                  </td>
                  <td>{res.signs[p] > 0 ? `#${a} outbid #${b}` : `#${b} outbid #${a}`}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  )
}
