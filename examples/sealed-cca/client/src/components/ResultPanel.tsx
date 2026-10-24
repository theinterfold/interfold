// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { type ClearingKind, useClearing } from '@/hooks/useClearing'
import { useChainTime } from '@/hooks/useChainTime'
import { type ClaimStep, type MyOutcome, useClaim } from '@/hooks/useClaim'
import {
  type SaleState,
  formatDateTime,
  formatDuration,
  formatPayment,
  formatPriceValue,
  formatSaleTokens,
  formatStepPrice,
} from '@/utils/sale'
import DemandChart, { demandAt } from './DemandChart'
import Spinner from './Spinner'

const KIND_TEXT: Record<ClearingKind, { title: string; body: string }> = {
  capped: {
    title: 'Capped at a price step',
    body: 'The demand at the clearing step is above the supply, and the demand just above it fits. Bidders above the step get their full tokens. Bidders at the step share what is left, in equal parts.',
  },
  uncapped: {
    title: 'Cleared between two steps',
    body: 'The demand falls between two steps. The clearing price lies between them and the whole supply sells. Every bidder at or above the upper step gets its full tokens and pays the escrow, less rounding.',
  },
  undersubscribed: {
    title: 'Undersubscribed',
    body: 'The demand at the lowest step is below the supply. Every bidder gets its full tokens at the lowest price. The creator takes back the unsold tokens.',
  },
}

const CLAIM_STEP_LABELS: Record<ClaimStep, string> = {
  proving: 'Proving your outcome in the browser…',
  sending: 'Claiming (confirm in your wallet)…',
  confirming: 'Waiting for the claim to be mined…',
}

interface ResultPanelProps {
  sale: SaleState
  account: `0x${string}` | undefined
}

/** The demand curve, the clearing and the outcome of the connected account, with its claim. */
const ResultPanel: React.FC<ResultPanelProps> = ({ sale, account }) => {
  const { counts, clearing, clear, clearBusy, error: clearError } = useClearing(sale)
  const claim = useClaim(sale, clearing, account)
  const now = useChainTime()
  const claimClosed = clearing !== null && now > clearing.claimDeadline
  const levels = sale.prices.length

  if (counts === null) {
    return clearError ? (
      <div className='note bad'>{clearError}</div>
    ) : (
      <div className='note flex items-center gap-3'>
        <Spinner size={16} /> Decoding the result in your browser…
      </div>
    )
  }

  return (
    <div className='space-y-8'>
      {clearing ? (
        <div className='grid gap-4 sm:grid-cols-3'>
          <div className='border border-ink bg-card p-5 sm:col-span-1'>
            <p className='mono-sm muted'>Clearing price</p>
            <p className='mt-1 font-serif text-4xl leading-none'>{formatPriceValue(sale, clearing.pStar)}</p>
            <p className='muted mt-2 text-xs'>
              {sale.paymentToken.symbol} for one {sale.saleToken.symbol}. Everyone pays this price.
            </p>
          </div>
          <div className='border border-accent bg-accent-soft p-5'>
            <p className='mono-sm muted'>Sold</p>
            <p className='mt-1 font-serif text-3xl leading-none'>{formatSaleTokens(sale, clearing.soldTotal)}</p>
            <p className='muted mt-2 text-xs'>of {formatSaleTokens(sale, sale.supply)}</p>
          </div>
          <div className='border border-rule-strong bg-card p-5'>
            <p className='mono-sm muted'>{KIND_TEXT[clearing.kind].title}</p>
            <p className='mt-2 text-xs text-ink-2'>{KIND_TEXT[clearing.kind].body}</p>
          </div>
        </div>
      ) : (
        <div className='note space-y-3'>
          <p>
            The committee published the demand curve. The sale is not cleared on chain yet. Anyone can clear it with one transaction. After
            that the price is fixed and bidders can claim.
          </p>
          <button onClick={() => void clear()} disabled={clearBusy || !account} className='btn sm'>
            {clearBusy ? (
              <>
                <Spinner size={12} /> Clearing…
              </>
            ) : (
              'Clear the sale'
            )}
          </button>
          {!account && <p className='text-xs'>Connect a wallet to send the transaction.</p>}
          {clearError && <p className='text-xs text-danger'>{clearError}</p>}
        </div>
      )}

      {clearing && (
        <div className={`note ${claimClosed ? 'warn' : ''}`}>
          {claimClosed ? (
            <>
              <strong>The claim window closed</strong> on {formatDateTime(clearing.claimDeadline)}. Claims no longer work. The creator can
              sweep every unclaimed token and escrow.
            </>
          ) : (
            <>
              <strong>Claim within {formatDuration(clearing.claimDeadline - now)}</strong> (until {formatDateTime(clearing.claimDeadline)}).
              After that the creator can sweep the unclaimed tokens and escrows, so claim in time.
            </>
          )}
        </div>
      )}

      <DemandChart sale={sale} counts={counts} clearing={clearing} myLevel={claim.outcome?.version?.level ?? null} />

      <div className='overflow-x-auto'>
        <table className='w-full text-left font-mono text-xs'>
          <thead className='text-ink-soft'>
            <tr>
              <th className='py-1 pr-4 font-normal'>Step</th>
              <th className='py-1 pr-4 font-normal'>Price ({sale.paymentToken.symbol})</th>
              <th className='py-1 pr-4 font-normal'>Bidders at or above</th>
              <th className='py-1 font-normal'>Demand ({sale.saleToken.symbol})</th>
            </tr>
          </thead>
          <tbody>
            {Array.from({ length: levels }, (_, level) => (
              <tr
                key={level}
                className={clearing && level === clearing.step && clearing.kind !== 'undersubscribed' ? 'font-semibold text-accent' : ''}
              >
                <td className='py-1 pr-4'>{level}</td>
                <td className='py-1 pr-4'>{formatStepPrice(sale, level)}</td>
                <td className='py-1 pr-4'>{counts[level].toString()}</td>
                <td className='py-1'>{demandAt(sale, counts, level).toLocaleString('en-US', { maximumFractionDigits: 4 })}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {account && clearing && (
        <MyOutcomePanel
          sale={sale}
          claimClosed={claimClosed}
          outcome={claim.outcome}
          step={claim.step}
          error={claim.error}
          onClaim={() => void claim.claim()}
        />
      )}
    </div>
  )
}

interface MyOutcomeProps {
  sale: SaleState
  claimClosed: boolean
  outcome: MyOutcome | null
  step: ClaimStep | null
  error: string | null
  onClaim: () => void
}

const ROLE_TEXT: Record<Exclude<MyOutcome['role'], 'none' | 'unknown'>, string> = {
  full: 'You get your full tokens.',
  marginal:
    'You bid at the clearing step. You share the last tokens with the other bidders at the step, so you get part of your tokens and a refund.',
  loser: 'Your highest price was below the clearing price. You get your whole escrow back.',
  dropped: 'No bid of yours counted: none of its ciphertexts opened its commitment, or you did not bid. You get your whole escrow back.',
}

const MyOutcomePanel: React.FC<MyOutcomeProps> = ({ sale, claimClosed, outcome, step, error, onClaim }) => {
  if (outcome === null) {
    return (
      <div className='note flex items-center gap-3'>
        <Spinner size={16} /> Reading your outcome…
      </div>
    )
  }
  if (outcome.role === 'none') return <div className='note'>This account did not deposit in this sale.</div>

  const amounts = outcome.result ?? outcome.preview
  return (
    <div className='space-y-4'>
      <h3 className='h3'>Your outcome</h3>
      {outcome.role === 'unknown' ? (
        <div className='note bad'>
          A bid of this account counted (version {outcome.counted}), but this browser does not hold its price and its salt. Only the browser
          that made the bid can prove the outcome and claim.
        </div>
      ) : (
        <div className={`note ${outcome.role === 'full' ? 'ok' : ''}`}>
          <p>
            <strong>
              {outcome.role === 'full'
                ? 'You won.'
                : outcome.role === 'marginal'
                  ? 'You won a part.'
                  : outcome.role === 'loser'
                    ? 'You did not win.'
                    : 'Your bid was dropped.'}
            </strong>{' '}
            {ROLE_TEXT[outcome.role]}
          </p>
          {outcome.version && outcome.role !== 'dropped' && (
            <p className='mt-1 text-xs'>
              Your highest price was {formatStepPrice(sale, outcome.version.level)} {sale.paymentToken.symbol}.
            </p>
          )}
        </div>
      )}

      {amounts && (
        <dl className='grid grid-cols-3 gap-4'>
          <div>
            <dt className='mono-sm muted'>Tokens</dt>
            <dd className='mt-1 font-serif text-2xl'>{formatSaleTokens(sale, amounts.tokens)}</dd>
          </div>
          <div>
            <dt className='mono-sm muted'>You pay</dt>
            <dd className='mt-1 font-serif text-2xl'>{formatPayment(sale, amounts.paid)}</dd>
          </div>
          <div>
            <dt className='mono-sm muted'>Refund</dt>
            <dd className='mt-1 font-serif text-2xl'>{formatPayment(sale, amounts.refund)}</dd>
          </div>
        </dl>
      )}

      {outcome.claimed ? (
        <div className='note ok'>Claimed. The tokens and the refund are in your account.</div>
      ) : (
        outcome.role !== 'unknown' && (
          <div className='space-y-2'>
            {error && <div className='note bad'>{error}</div>}
            <button onClick={onClaim} disabled={step !== null || claimClosed} className='btn accent lg block'>
              {step ? (
                <>
                  <Spinner size={14} /> {CLAIM_STEP_LABELS[step]}
                </>
              ) : claimClosed ? (
                'Claim window closed'
              ) : (
                'Claim'
              )}
            </button>
            <p className='muted text-xs'>
              {outcome.role === 'dropped'
                ? 'No proof is needed.'
                : 'The claim proof runs in this tab and takes a few seconds. It shows the contract whether your price is below, at, or above the clearing step, and nothing else.'}
            </p>
          </div>
        )
      )}
      {outcome.role === 'unknown' && error && <div className='note bad'>{error}</div>}
    </div>
  )
}

export default ResultPanel
