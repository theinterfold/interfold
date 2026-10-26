// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { Role } from '@interfold/negotiation'
import { useSettle } from '@/hooks/useSettle'
import { type NegotiationPhase, type NegotiationState, formatPrice } from '@/utils/negotiation'
import Spinner from './Spinner'

interface ResultPanelProps {
  negotiation: NegotiationState
  phase: NegotiationPhase
  account: `0x${string}` | undefined
  role: Role | null
  /** Re-read the chain after `settle` is mined. */
  onSettled: () => void
}

/** What a party learns from the result, in plain words. */
function learned(negotiation: NegotiationState, role: Role | null): string[] {
  const { matched, price } = negotiation.outcome
  const p = formatPrice(negotiation, price)
  if (!matched) {
    return ['The buyer’s maximum is below the seller’s minimum. Nothing more.']
  }
  const seller = `The seller learns only that the buyer’s maximum is at least ${p}.`
  const buyer = `The buyer learns only that the seller’s minimum is at most ${p}.`
  if (role === Role.Seller) return [seller]
  if (role === Role.Buyer) return [buyer]
  return [seller, buyer]
}

const STAYS_PRIVATE_MATCH = [
  'The seller’s minimum price, except that it is at most the agreed price.',
  'The buyer’s maximum price, except that it is at least the agreed price.',
]

const STAYS_PRIVATE_NO_MATCH = ['The seller’s minimum price.', 'The buyer’s maximum price.']

/** The outcome after `settle`, or the button that settles it once the committee has published the output. */
const ResultPanel: React.FC<ResultPanelProps> = ({ negotiation, phase, account, role, onSettled }) => {
  const { settle, busy, error } = useSettle(negotiation.e3Id, account, onSettled)

  if (phase === 'failed') return <div className='note'>There is no result: the negotiation failed.</div>

  if (phase === 'settling') {
    return (
      <div className='note space-y-3'>
        <p>
          The committee published the output. It is not settled on chain yet. Anyone can settle it with one transaction. The contract checks
          that the output is a valid result, and stores it.
        </p>
        <button onClick={() => void settle()} disabled={busy || !account} className='btn sm'>
          {busy ? (
            <>
              <Spinner size={12} /> Settling…
            </>
          ) : (
            'Settle'
          )}
        </button>
        {!account && <p className='text-xs'>Connect a wallet to send the transaction.</p>}
        {error && <p className='text-xs text-danger'>{error}</p>}
      </div>
    )
  }

  if (phase !== 'settled') {
    return (
      <div className='note flex items-start gap-3'>
        <Spinner size={16} />
        <span>
          The result appears once the offer window has closed, the program has combined the two offers and the committee has decrypted the
          output. That takes a few minutes after the window closes.
        </span>
      </div>
    )
  }

  const { matched, price } = negotiation.outcome
  return (
    <div className='space-y-8'>
      {matched ? (
        <div className='border border-accent bg-accent-soft p-6'>
          <p className='mono-sm muted'>Agreed price</p>
          <p className='mt-1 font-serif text-5xl leading-none'>{formatPrice(negotiation, price)}</p>
          <p className='muted mt-3 text-sm'>The buyer’s maximum is at least this price and the seller’s minimum is at most this price.</p>
        </div>
      ) : (
        <div className='border border-ink bg-card p-6'>
          <p className='mono-sm muted'>Result</p>
          <p className='mt-1 font-serif text-5xl leading-none'>No match</p>
          <p className='muted mt-3 text-sm'>The buyer’s maximum is below the seller’s minimum.</p>
        </div>
      )}

      <div className='grid gap-6 sm:grid-cols-2'>
        <div className='card flat space-y-2'>
          <p className='mono-sm muted'>What {role === null ? 'the parties' : 'you'} learned</p>
          <ul className='list-disc space-y-1 pl-5 text-sm'>
            {learned(negotiation, role).map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </div>
        <div className='card flat space-y-2'>
          <p className='mono-sm muted'>What stays private</p>
          <ul className='list-disc space-y-1 pl-5 text-sm'>
            {(matched ? STAYS_PRIVATE_MATCH : STAYS_PRIVATE_NO_MATCH).map((line) => (
              <li key={line}>{line}</li>
            ))}
            <li>The offers themselves. They were never decrypted.</li>
          </ul>
        </div>
      </div>
      {matched && (
        <p className='muted text-xs'>
          The agreed price is almost uniform over the prices that both parties accept. It is not exactly uniform: see How it works.
        </p>
      )}
    </div>
  )
}

export default ResultPanel
