// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useEffect, useState } from 'react'
import { useWalletClient } from 'wagmi'
import { useChainTime } from '@/hooks/useChainTime'
import { chain } from '@/utils/chain'
import { formatError } from '@/utils/error-formatting'
import { Phase, formatDuration, isRefundPhase } from '@/utils/phase'
import { type SaleAction, sendSaleAction } from '@/utils/program-tx'
import {
  type ClearingKind,
  type SaleState,
  formatBudget,
  formatDateTime,
  formatPriceValue,
  formatSaleTokens,
  formatStepPrice,
  readRevealedSums,
} from '@/utils/sale'
import ProbeChart from './ProbeChart'
import Spinner from './Spinner'

const KIND_TEXT: Record<ClearingKind, { title: string; body: string }> = {
  capped: {
    title: 'Capped at a price step',
    body: 'The budgets at the clearing step buy more than the supply, and the budgets above it do not. Bids above the step get their full tokens. Bids at the step fill in bid order until the tokens run out.',
  },
  uncapped: {
    title: 'Cleared between two steps',
    body: 'The demand falls between two steps. The clearing price lies between them and the whole supply sells. Bids at or above the upper step get their tokens.',
  },
  undersubscribed: {
    title: 'Undersubscribed',
    body: 'The budgets at the lowest step buy less than the supply. Every counted bid gets its tokens at the lowest price. The creator takes back the unsold tokens.',
  },
}

/** The steps whose bit is set in a probe mask. */
const levelsOf = (mask: number, levels: number): number[] =>
  Array.from({ length: levels }, (_, level) => level).filter((level) => (mask >> level) & 1)

const popcount = (value: bigint): number => value.toString(2).replace(/0/g, '').length

interface ResultPanelProps {
  sale: SaleState
  /** The max price step of the viewer's bid, if this browser holds it: the chart marks it. */
  myStep: number | null
  /** Re-read the sale after a transaction. */
  onChanged: () => void
}

/** The progress of the probe search and the public result: revealed sums, the clearing and the total sold. No bid is shown. */
const ResultPanel: React.FC<ResultPanelProps> = ({ sale, myStep, onChanged }) => {
  const { data: walletClient } = useWalletClient({ chainId: chain.id })
  const now = useChainTime()
  const [sums, setSums] = useState<(bigint | null)[] | null>(null)
  const [busy, setBusy] = useState<SaleAction | null>(null)
  const [error, setError] = useState<string | null>(null)
  const { phase, clearing, probes, levels } = sale

  const cleared = clearing !== null
  useEffect(() => {
    setSums(null)
    if (phase < Phase.Round2 || isRefundPhase(phase)) return
    let cancelled = false
    readRevealedSums(sale)
      .then((next) => {
        if (!cancelled) setSums(next)
      })
      .catch((err) => console.warn('Could not read the revealed sums:', err))
    return () => {
      cancelled = true
    }
    // `sale` is read for its id, its probes and its clearing: the dependencies name them.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sale.saleId, phase, cleared, probes?.probeMask1])

  const send = async (action: SaleAction) => {
    if (!walletClient) return
    setBusy(action)
    setError(null)
    try {
      await sendSaleAction(walletClient, action, sale.saleId)
      onChanged()
    } catch (err) {
      setError(formatError(err))
    } finally {
      setBusy(null)
    }
  }

  if (isRefundPhase(phase)) return <div className='note bad'>There is no result. {sale.stopReason}</div>
  if (phase < Phase.Probing) {
    return (
      <div className='note flex items-start gap-3'>
        <Spinner size={16} />
        <span>
          The result appears in steps. After the bidding window closes, round 1 reveals a few budget sums. Round 2 reveals a few more. Then
          the sale clears. This takes a few minutes.
        </span>
      </div>
    )
  }

  const known = sums?.filter((sum) => sum !== null).length ?? 0
  const claimClosed = clearing !== null && now > clearing.claimDeadline

  return (
    <div className='space-y-8'>
      {probes && (
        <div className='note space-y-1'>
          <p>
            <strong>Round 1</strong> revealed the budget sums at steps {levelsOf(probes.probeMask1, levels).join(', ')}. The clearing step
            lies between step {probes.lo} and step {probes.hi}.
          </p>
          {phase >= Phase.Round2 && (
            <p>
              <strong>Round 2</strong> reveals the sums at steps {levelsOf(probes.probeMask2, levels).join(', ') || 'none'}.
            </p>
          )}
          {sums && (
            <p className='text-xs'>
              {known} of {levels} price steps are known. The other {levels - known} stay private.
            </p>
          )}
        </div>
      )}

      {phase === Phase.Probing && (
        <div className='note space-y-3'>
          <p>Round 1 is decrypted. One transaction publishes the probes for round 2. Anyone can send it. The server sends it too.</p>
          <button onClick={() => void send('publishProbes')} disabled={busy !== null || !walletClient} className='btn sm'>
            {busy === 'publishProbes' ? (
              <>
                <Spinner size={12} /> Publishing…
              </>
            ) : (
              'Publish the probes'
            )}
          </button>
          {!walletClient && <p className='text-xs'>Connect a wallet to send the transaction.</p>}
        </div>
      )}

      {phase === Phase.Clearable && (
        <div className='note space-y-3'>
          <p>Round 2 is decrypted. One transaction clears the sale. Anyone can send it. The server sends it too.</p>
          <button onClick={() => void send('clear')} disabled={busy !== null || !walletClient} className='btn sm'>
            {busy === 'clear' ? (
              <>
                <Spinner size={12} /> Clearing…
              </>
            ) : (
              'Clear the sale'
            )}
          </button>
          {!walletClient && <p className='text-xs'>Connect a wallet to send the transaction.</p>}
        </div>
      )}
      {error && <div className='note bad'>{error}</div>}

      {clearing && (
        <>
          <div className='grid gap-4 sm:grid-cols-3'>
            <div className='border border-ink bg-card p-5'>
              <p className='mono-sm muted'>Clearing price</p>
              <p className='mt-1 font-serif text-4xl leading-none'>{formatPriceValue(sale, clearing.pStar)}</p>
              <p className='muted mt-2 text-xs'>
                {sale.paymentToken.symbol} for one {sale.saleToken.symbol}. Everyone pays this price.
                {clearing.kind !== 'undersubscribed' &&
                  ` Clearing step: ${clearing.step} (${formatStepPrice(sale, clearing.step)} ${sale.paymentToken.symbol}).`}
              </p>
            </div>
            <div className='border border-accent bg-accent-soft p-5'>
              <p className='mono-sm muted'>Sold</p>
              <p className='mt-1 font-serif text-3xl leading-none'>{formatSaleTokens(sale, clearing.sold)}</p>
              <p className='muted mt-2 text-xs'>of {formatSaleTokens(sale, sale.supply)}</p>
            </div>
            <div className='border border-rule-strong bg-card p-5'>
              <p className='mono-sm muted'>{KIND_TEXT[clearing.kind].title}</p>
              <p className='mt-2 text-xs text-ink-2'>{KIND_TEXT[clearing.kind].body}</p>
            </div>
          </div>
          <p className='muted text-sm'>
            {popcount(clearing.countedMask)} of {sale.bidCount} bids counted. A bid counts when it opens its commitment in both rounds.
          </p>
          {clearing.kind === 'capped' && (
            <div className='note'>
              <strong>Bids at clearing step {clearing.step} fill in bid order.</strong>{' '}
              {now <= clearing.marginalDeadline
                ? `Such a bid must register its claim until ${formatDateTime(clearing.marginalDeadline)} (${formatDuration(clearing.marginalDeadline - now)} left). A registration is public. After that anyone can pay the registered claims.`
                : `The registration window closed on ${formatDateTime(clearing.marginalDeadline)}. Anyone can pay the registered claims. A bid at the step that did not register gets its escrow back and no tokens.`}
            </div>
          )}
          <div className={`note ${claimClosed ? 'warn' : ''}`}>
            {claimClosed ? (
              <>
                <strong>The claim window closed</strong> on {formatDateTime(clearing.claimDeadline)}. The creator can sweep every unclaimed
                token and escrow.
              </>
            ) : (
              <>
                <strong>Claim within {formatDuration(clearing.claimDeadline - now)}</strong> (until {formatDateTime(clearing.claimDeadline)}
                ). After that the creator can sweep the unclaimed tokens and escrows.
              </>
            )}
          </div>
        </>
      )}

      {phase < Phase.Round2 ? null : sums ? (
        <>
          <ProbeChart sale={sale} sums={sums} clearing={clearing} myStep={myStep} />
          <div className='overflow-x-auto'>
            <table className='w-full text-left font-mono text-xs'>
              <thead className='text-ink-soft'>
                <tr>
                  <th className='py-1 pr-4 font-normal'>Step</th>
                  <th className='py-1 pr-4 font-normal'>Price ({sale.paymentToken.symbol})</th>
                  <th className='py-1 font-normal'>Budgets at or above (units)</th>
                </tr>
              </thead>
              <tbody>
                {sums.map((sum, step) => (
                  <tr
                    key={step}
                    className={clearing && step === clearing.step && clearing.kind !== 'undersubscribed' ? 'font-semibold text-accent' : ''}
                  >
                    <td className='py-1 pr-4'>{step}</td>
                    <td className='py-1 pr-4'>{formatStepPrice(sale, step)}</td>
                    <td className='py-1'>{sum === null ? 'not revealed' : `${sum.toString()} (${formatBudget(sale, sum)})`}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      ) : (
        <div className='note flex items-center gap-3'>
          <Spinner size={16} /> Reading the revealed sums…
        </div>
      )}
    </div>
  )
}

export default ResultPanel
