// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { Outcome, cost } from '@interfold/private-round'
import { type Clearing, useClearing } from '@/hooks/useClearing'
import { useChainTime } from '@/hooks/useChainTime'
import { type ClaimAction, type ClaimStep, type MyOutcome, actionOf, resolveClaim, useClaim } from '@/hooks/useClaim'
import {
  type SaleState,
  formatDateTime,
  formatDuration,
  formatPayment,
  formatPriceValue,
  formatSaleTokens,
  formatStepPrice,
} from '@/utils/sale'
import Spinner from './Spinner'

const CLAIM_STEP_LABELS: Record<ClaimStep, string> = {
  proving: 'Proving your outcome in the browser…',
  sending: 'Sending (confirm in your wallet)…',
  confirming: 'Waiting for the transaction to be mined…',
}

/** The words for an outcome, for the card at the top of the result. */
function outcomeText(sale: SaleState, outcome: Outcome, step: number): { title: string; body: string } {
  switch (outcome) {
    case Outcome.SoldOut:
      return {
        title: `Sold out at ${formatPriceValue(sale, sale.prices[step])} ${sale.paymentToken.symbol}`,
        body: `At least ${sale.lots} bidders accepted this price step or a higher one. Everyone who gets a lot pays the price of step ${step}. Bidders above step ${step} get a lot. Bidders at step ${step} compete for the lots that are left: the first ones by deposit order get a whole lot.`,
      }
    case Outcome.Undersubscribed:
      return {
        title: `Undersubscribed, sold at ${formatPriceValue(sale, sale.prices[sale.reserveStep])} ${sale.paymentToken.symbol}`,
        body: `The reserve was met, but fewer than ${sale.lots} bidders accepted the reserve price. Every counted bidder at or above the reserve gets one lot at the reserve price. The creator takes back the lots that did not sell.`,
      }
    case Outcome.NotMet:
      return {
        title: 'Reserve not met',
        body: `Fewer than ${sale.minLots} bidders accepted the reserve price. Nothing sells and everyone gets the escrow back. The program reveals nothing else.`,
      }
    default:
      return {
        title: 'Round aborted',
        body: 'The decrypted output was not a valid result of the program. The contract treats it like a round that did not meet its reserve: everyone gets the escrow back.',
      }
  }
}

interface ResultPanelProps {
  sale: SaleState
  account: `0x${string}` | undefined
}

/** The outcome of the round, what is public, and the claim flow of the connected account. */
const ResultPanel: React.FC<ResultPanelProps> = ({ sale, account }) => {
  const { preview, clearing, clear, clearBusy, error: clearError } = useClearing(sale)
  const claim = useClaim(sale, clearing, account)
  const now = useChainTime()

  const view = clearing
    ? { outcome: clearing.outcome, step: clearing.step, counted: clearing.counted }
    : preview
      ? { outcome: preview.outcome, step: preview.step ?? 0, counted: preview.counted }
      : null
  if (view === null) {
    return clearError ? (
      <div className='note bad'>{clearError}</div>
    ) : (
      <div className='note flex items-center gap-3'>
        <Spinner size={16} /> Decoding the result in your browser…
      </div>
    )
  }
  const { outcome, step, counted } = view
  const text = outcomeText(sale, outcome, step)
  const sells = outcome === Outcome.SoldOut || outcome === Outcome.Undersubscribed
  const pStar = outcome === Outcome.SoldOut ? sale.prices[step] : outcome === Outcome.Undersubscribed ? sale.prices[sale.reserveStep] : 0n

  return (
    <div className='space-y-8'>
      <div className={`border p-5 ${sells ? 'border-accent bg-accent-soft' : 'border-ink bg-card'}`}>
        <p className='mono-sm muted'>Outcome</p>
        <p className='mt-1 font-serif text-3xl leading-tight'>{text.title}</p>
        <p className='mt-2 text-sm text-ink-2'>{text.body}</p>
        {sells && (
          <p className='mt-3 font-mono text-xs'>
            One lot is {formatSaleTokens(sale, sale.lot)} and costs {formatPayment(sale, cost(sale.lot, pStar, sale.saleToken.decimals))}.
          </p>
        )}
      </div>

      {!clearing && (
        <div className='note space-y-3'>
          <p>
            The committee published the result. The round is not cleared on chain yet. Anyone can clear it with one transaction. After that
            the price is fixed and the claims open.
          </p>
          <button onClick={() => void clear()} disabled={clearBusy || !account} className='btn sm'>
            {clearBusy ? (
              <>
                <Spinner size={12} /> Clearing…
              </>
            ) : (
              'Clear the round'
            )}
          </button>
          {!account && <p className='text-xs'>Connect a wallet to send the transaction.</p>}
          {clearError && <p className='text-xs text-danger'>{clearError}</p>}
        </div>
      )}

      <PublicPanel sale={sale} outcome={outcome} step={step} counted={counted} />

      {clearing && <ClaimWindows sale={sale} clearing={clearing} now={now} />}

      {account && clearing && (
        <MyOutcomePanel
          sale={sale}
          clearing={clearing}
          now={now}
          outcome={claim.outcome}
          step={claim.step}
          error={claim.error}
          onClaim={() => void claim.claim()}
          onSettle={() => void claim.settle()}
        />
      )}
    </div>
  )
}

/** What the chain and the committee reveal. Everything else stays hidden. */
const PublicPanel: React.FC<{ sale: SaleState; outcome: Outcome; step: number; counted: number }> = ({ sale, outcome, step, counted }) => {
  const met = outcome === Outcome.Undersubscribed || outcome === Outcome.SoldOut
  return (
    <div className='card flat space-y-4'>
      <p className='mono muted'>What is public</p>
      <dl className='grid gap-4 sm:grid-cols-3'>
        <div>
          <dt className='mono-sm muted'>Reserve met</dt>
          <dd className='mt-1 font-serif text-2xl'>{outcome === Outcome.Aborted ? 'Unknown' : met ? 'Yes' : 'No'}</dd>
          <dd className='muted text-xs'>
            At least {sale.minLots} bidder{sale.minLots === 1 ? '' : 's'} at step {sale.reserveStep} or above.
          </dd>
        </div>
        <div>
          <dt className='mono-sm muted'>Clearing step</dt>
          <dd className='mt-1 font-serif text-2xl'>
            {outcome === Outcome.SoldOut ? `${step} (${formatStepPrice(sale, step)} ${sale.paymentToken.symbol})` : 'None'}
          </dd>
          <dd className='muted text-xs'>
            {outcome === Outcome.SoldOut
              ? 'The highest step that at least ' + sale.lots + ' bidders accept.'
              : outcome === Outcome.Undersubscribed
                ? `Not sold out: the price is the reserve step ${sale.reserveStep}.`
                : 'Nothing sells.'}
          </dd>
        </div>
        <div>
          <dt className='mono-sm muted'>Bids counted</dt>
          <dd className='mt-1 font-serif text-2xl'>{counted}</dd>
          <dd className='muted text-xs'>Bidders whose latest valid bid counted.</dd>
        </div>
      </dl>
      <p className='text-sm text-ink-2'>
        There is no demand curve. The program does not publish how many bidders accept each price. It does not publish any price that a
        bidder named, and not the order of the bids. The claims show a little more over time: an above or a marginal claim shows that its
        bidder bid above or at the clearing step. A bidder at the clearing step shows that it bid exactly that step when it registers. Its
        deposit index is public already.
      </p>
    </div>
  )
}

/** The two windows after the clearing, and the claim deadline, with the one that runs now marked. */
const ClaimWindows: React.FC<{ sale: SaleState; clearing: Clearing; now: bigint }> = ({ sale, clearing, now }) => {
  if (clearing.outcome !== Outcome.SoldOut && clearing.outcome !== Outcome.Undersubscribed) {
    return (
      <div className={`note ${now > clearing.claimDeadline ? 'warn' : ''}`}>
        {now > clearing.claimDeadline ? (
          <>
            <strong>The claim window closed</strong> on {formatDateTime(clearing.claimDeadline)}. The creator can take back the supply and
            sweep the escrows that nobody claimed.
          </>
        ) : (
          <>
            <strong>Refund your escrow within {formatDuration(clearing.claimDeadline - now)}</strong> (until{' '}
            {formatDateTime(clearing.claimDeadline)}). No proof is needed.
          </>
        )}
      </div>
    )
  }
  const soldOut = clearing.outcome === Outcome.SoldOut
  const rows: { key: string; title: string; text: string; active: boolean; done: boolean }[] = soldOut
    ? [
        {
          key: 'p1',
          title: 'Phase 1: bidders above the clearing step',
          text: `Up to ${formatDateTime(clearing.phase1End)}. Bidders above step ${clearing.step} claim their lot now. ${clearing.aboveClaimed} claimed so far.`,
          active: now <= clearing.phase1End,
          done: now > clearing.phase1End,
        },
        {
          key: 'p2',
          title: 'Phase 2: bidders at the clearing step',
          text: `Up to ${formatDateTime(clearing.phase2End)}. Bidders at step ${clearing.step} register. Their escrow stays locked. ${clearing.marginalRegistered} registered so far.`,
          active: now > clearing.phase1End && now <= clearing.phase2End,
          done: now > clearing.phase2End,
        },
        {
          key: 'settle',
          title: 'Settlement of the marginal bidders',
          text: `After phase 2 the ${sale.lots - clearing.aboveClaimed} lots that are left go to the first registered bidders by deposit order, one whole lot each, at the clearing price. The other registered bidders get their whole escrow back. A lot is never split.`,
          active: now > clearing.phase2End && now <= clearing.claimDeadline,
          done: false,
        },
      ]
    : [
        {
          key: 'claim',
          title: 'Claims',
          text: 'Every counted bidder at or above the reserve claims one lot. Other bidders claim the refund.',
          active: now <= clearing.claimDeadline,
          done: false,
        },
      ]
  return (
    <div className='space-y-3'>
      <ol className='steps'>
        {rows.map((row, index) => (
          <li key={row.key} className={`step ${row.done ? 'done' : row.active ? 'active' : 'todo'}`}>
            <span className='pin'>{index + 1}</span>
            <div>
              <p className={`font-semibold ${row.done || row.active ? 'text-ink' : ''}`}>{row.title}</p>
              <p className='text-sm'>{row.text}</p>
            </div>
          </li>
        ))}
      </ol>
      <div className={`note ${now > clearing.claimDeadline ? 'warn' : ''}`}>
        {now > clearing.claimDeadline ? (
          <>
            <strong>The claim window closed</strong> on {formatDateTime(clearing.claimDeadline)}. Claims no longer work. The creator can
            sweep every unclaimed token and escrow.
          </>
        ) : (
          <>
            <strong>Claim within {formatDuration(clearing.claimDeadline - now)}</strong> (until {formatDateTime(clearing.claimDeadline)}).
            After that the creator can sweep the unclaimed tokens and escrows.
          </>
        )}
      </div>
    </div>
  )
}

interface MyOutcomeProps {
  sale: SaleState
  clearing: Clearing
  now: bigint
  outcome: MyOutcome | null
  step: ClaimStep | null
  error: string | null
  onClaim: () => void
  onSettle: () => void
}

/** The place of a bidder in the deposit order of the registered bidders: `rank` counts from 0. */
function ordinal(rank: number | null): string {
  return rank === null ? 'your place' : `place ${rank + 1}`
}

const CLASS_TEXT = {
  full: { head: 'You get a lot.', body: 'You get one lot at the clearing price, and the rest of your escrow back.' },
  marginal: {
    head: 'You are at the clearing step.',
    body: 'You bid exactly the clearing step. The bidders above the step take their lots first. The lots that are left go to the first registered bidders by deposit order: one whole lot each. If you are not among them, you get your whole escrow back. You register in phase 2 and settle after it. When you register, everyone sees that you bid exactly the clearing step. Your deposit index is public already.',
  },
  refund: { head: 'No lot for you.', body: 'You get your whole escrow back.' },
} as const

const REFUND_REASON: Record<MyOutcome['standing'], string> = {
  'not-deposited': '',
  'not-counted': 'No bid of yours counted: none of its ciphertexts opened its commitment, or you did not bid.',
  failed: 'The reserve was not met, so nobody gets a lot.',
  bid: '',
  'unknown-bid': '',
  'no-proof': '',
}

const MyOutcomePanel: React.FC<MyOutcomeProps> = ({ sale, clearing, now, outcome, step, error, onClaim, onSettle }) => {
  if (outcome === null) {
    return (
      <div className='note flex items-center gap-3'>
        <Spinner size={16} /> Reading your outcome…
      </div>
    )
  }
  if (outcome.standing === 'not-deposited') return <div className='note'>This account did not deposit in this round.</div>

  const { cls, amounts: previewAmounts } = resolveClaim(outcome, clearing, sale.escrow, now)
  const action: ClaimAction = actionOf(outcome, clearing, sale.escrow, now)
  const amounts = outcome.result ?? previewAmounts
  const busy = step !== null

  return (
    <div className='space-y-4'>
      <h3 className='h3'>Your outcome</h3>
      {outcome.standing === 'unknown-bid' ? (
        <div className='note bad'>
          A bid of this account counted (version {outcome.counted}), but this browser does not hold its price and its salt. Only the browser
          that made the bid can prove the outcome and claim.
        </div>
      ) : (
        cls && (
          <div className={`note ${cls === 'full' ? 'ok' : ''}`}>
            <p>
              <strong>{CLASS_TEXT[cls].head}</strong> {REFUND_REASON[outcome.standing] || CLASS_TEXT[cls].body}
            </p>
            {outcome.version && outcome.standing === 'bid' && (
              <p className='mt-1 text-xs'>
                Your price was step {outcome.version.level}: {formatStepPrice(sale, outcome.version.level)} {sale.paymentToken.symbol}.
              </p>
            )}
          </div>
        )
      )}

      {amounts && (
        <div className='space-y-1'>
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
          {!outcome.claimed && cls === 'marginal' && (
            <p className='muted text-xs'>
              {outcome.filled
                ? `Filled for now: ${ordinal(outcome.rank)} of the registered bidders by deposit order gets a lot.`
                : `Refund for now: ${ordinal(outcome.rank)} of the registered bidders by deposit order, and no lot is left for that place.`}{' '}
              This changes while bidders register. It is final when phase 2 ends.
            </p>
          )}
        </div>
      )}

      {outcome.claimed ? (
        <div className='note ok'>Claimed. The tokens and the refund are in your account.</div>
      ) : action.kind === 'wait' || action.kind === 'none' ? (
        <div className='space-y-2'>
          {error && <div className='note bad'>{error}</div>}
          <div className='note'>
            {action.text}
            {action.kind === 'wait' && (
              <>
                {' '}
                <span className='font-mono'>
                  ({formatDuration(action.until - now)} left, at {formatDateTime(action.until)})
                </span>
              </>
            )}
          </div>
        </div>
      ) : (
        <div className='space-y-2'>
          {error && <div className='note bad'>{error}</div>}
          {action.kind === 'claim' && action.forfeit && <div className='note warn'>{action.forfeit}</div>}
          {action.note && <p className='muted text-xs'>{action.note}</p>}
          <button onClick={action.kind === 'settle' ? onSettle : onClaim} disabled={busy} className='btn accent lg block'>
            {step ? (
              <>
                <Spinner size={14} /> {CLAIM_STEP_LABELS[step]}
              </>
            ) : (
              action.label
            )}
          </button>
          {action.kind !== 'settle' && outcome.proofNeeded && (
            <p className='muted text-xs'>
              The claim proof runs in this tab and takes a few seconds. It shows the contract whether your price is below, at, or above the
              clearing step, and nothing else.
            </p>
          )}
          {!outcome.proofNeeded && <p className='muted text-xs'>No proof is needed.</p>}
        </div>
      )}
    </div>
  )
}

export default ResultPanel
