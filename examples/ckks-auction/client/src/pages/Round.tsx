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

import { api } from '../api'
import { useBid } from '../hooks/useBid'
import { useWallet } from '../wallet'

const statusBadge = (s: RoundDetail['status']) => (s === 'finished' ? 'ok' : s === 'failed' ? 'bad' : s === 'active' ? 'ok' : 'info')

export const Round = () => {
  const { id = '' } = useParams()
  const qc = useQueryClient()
  const round = useQuery({ queryKey: ['round', id], queryFn: () => api.round(id), refetchInterval: 3000 })
  const evaluate = useMutation({ mutationFn: () => api.evaluate(id), onSuccess: () => qc.invalidateQueries({ queryKey: ['round', id] }) })
  if (round.isLoading || !round.data) return <p className="muted">loading round #{id}…</p>
  const r = round.data
  return (
    <>
      <h1>
        Round #{r.e3Id} <span className={`badge ${statusBadge(r.status)}`} data-testid="round-status">{r.status}</span>
      </h1>
      <div className="grid">
        <div className="panel">
          <h3>Round</h3>
          <div className="mono">program {r.programAddress}</div>
          <div className="mono">balance root {r.balanceRoot ?? '—'}</div>
          <div>
            bidding window {new Date(r.inputWindow[0] * 1000).toLocaleTimeString()} → {new Date(r.inputWindow[1] * 1000).toLocaleTimeString()}
          </div>
          <div>
            committee key {r.publicKeyAvailable ? <span className="badge ok">published</span> : <span className="badge warn">DKG in progress</span>} · relin ceremony{' '}
            <span className={`badge ${r.ceremonyKeys >= r.ceremonyKeysExpected ? 'ok' : 'warn'}`}>
              {r.ceremonyKeys}/{r.ceremonyKeysExpected} keys
            </span>
          </div>
          {r.error && <div className="badge bad" style={{ marginTop: 6 }}>{r.error}</div>}
        </div>
        <div className="panel">
          <h3>Balance snapshot</h3>
          <table>
            <tbody>
              {r.snapshot.map((h) => (
                <tr key={h.address}>
                  <td className="mono">{h.address}</td>
                  <td>{h.balance}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <BidPanel round={r} />

      <h2>Accepted bids ({r.bids.length})</h2>
      <div className="panel">
        <table>
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
                <td>{b.index}</td>
                <td className="mono">{b.publisher}</td>
                <td className="mono">{b.transactionHash.slice(0, 14)}…</td>
                <td className="mono">{b.uCommitment.slice(0, 14)}…</td>
                <td>{b.ciphertextAvailable ? <span className="badge ok">verified on-chain</span> : <span className="badge bad">missing</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {(r.status === 'active' || r.status === 'evaluating') && r.bids.length >= 2 && (
          <div className="row" style={{ marginTop: 8 }}>
            <button data-testid="evaluate" className="secondary" disabled={evaluate.isPending} onClick={() => evaluate.mutate()}>
              {evaluate.isPending ? 'evaluating…' : 'Evaluate now (admin)'}
            </button>
            {evaluate.isError && <span className="badge bad">{(evaluate.error as Error).message}</span>}
          </div>
        )}
      </div>

      {r.results && <Results round={r} />}

      {Object.keys(r.timings).length > 0 && (
        <>
          <h2>Timings</h2>
          <div className="panel">
            <table>
              <tbody>
                {Object.entries(r.timings).map(([k, v]) => (
                  <tr key={k}>
                    <td className="mono">{k}</td>
                    <td>{v}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
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

  return (
    <>
      <h2>Place a bid</h2>
      <div className="panel">
        {!address && <p className="muted">Connect a wallet to bid. Your bid is encrypted and proven in this browser and sent from your own key.</p>}
        {address && !mine && <p className="badge bad">{address} is not in this round's balance snapshot</p>}
        {address && mine && (
          <p>
            Attested balance for <span className="mono">{address}</span>: <b data-testid="my-balance">{mine.balance}</b> — you can bid at most that.
            {alreadyBid && <span className="badge info" style={{ marginLeft: 8 }}>you already bid in this round</span>}
          </p>
        )}
        <div className="row">
          <input data-testid="bid-input" type="number" placeholder="bid" value={bid} onChange={(e) => setBid(e.target.value)} disabled={!canBid} />
          <button data-testid="bid-submit" disabled={!canBid || !bid} onClick={() => submit(Number(bid)).catch(() => {})}>
            {state.running ? 'proving…' : 'Encrypt, prove & submit'}
          </button>
          {round.status !== 'active' && <span className="muted">bidding is {round.status === 'requested' ? 'not open yet (DKG running)' : 'closed'}</span>}
        </div>
        {state.steps.length > 0 && (
          <ul className="steps" data-testid="bid-steps">
            {state.steps.map((s, i) => (
              <li key={i}>
                <span>
                  {s.status === 'running' ? '⏳' : s.status === 'done' ? '✅' : '❌'} {s.label}
                </span>
                <span className="mono">{s.ms !== undefined ? `${Math.round(s.ms)} ms` : ''}</span>
              </li>
            ))}
          </ul>
        )}
        {state.error && (
          <p className="badge bad" data-testid="bid-error">
            {state.error}
          </p>
        )}
        {state.txHash && (
          <p>
            <span className="badge ok" data-testid="bid-verified">verified on-chain</span> tx <span className="mono">{state.txHash}</span> · gas{' '}
            <span className="mono" data-testid="bid-gas">{state.gasUsed?.toString()}</span>
          </p>
        )}
        {state.submission && (
          <details>
            <summary className="muted">proof details</summary>
            <div className="mono">u_commitment {state.submission.uCommitment}</div>
            <div className="mono">m_commitment {state.submission.mCommitment}</div>
            <div className="mono">ciphertext {(state.submission.ciphertext.length - 2) / 2} bytes</div>
            <pre data-testid="bid-timings">{JSON.stringify(state.submission.timings, null, 1)}</pre>
          </details>
        )}
      </div>
    </>
  )
}

const Results = ({ round }: { round: RoundDetail }) => {
  const res = round.results!
  return (
    <>
      <h2>Results</h2>
      <div className="panel">
        <p className="winner" data-testid="winner">
          Winner: bidder #{res.winner} {res.winnerAddress && <span className="mono">({res.winnerAddress})</span>}
        </p>
        <p>
          Opened output: {res.binarized ? <span className="badge ok" data-testid="binarized">only saturated ±1 signs</span> : <span className="badge warn">unsaturated slot(s) — a gap below ~2% of the bound</span>}
        </p>
        <table className="signs" data-testid="sign-matrix">
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
                <td className="mono">({a}, {b})</td>
                <td className="mono">{res.values[p].toFixed(2)}</td>
                <td className={res.signs[p] > 0 ? 'pos' : 'neg'}>{res.signs[p] > 0 ? '+1' : '−1'}</td>
                <td>{res.signs[p] > 0 ? `#${a} outbid #${b}` : `#${b} outbid #${a}`}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="muted">wins per bidder: {res.wins.join(' / ')}</p>
      </div>
    </>
  )
}
