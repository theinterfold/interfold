// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { CheckCircleIcon, XCircleIcon } from '@phosphor-icons/react'
import { Phase, TIMELINE, isRefundPhase, timelineIndex } from '@/utils/phase'
import { type SaleState, formatDateTime } from '@/utils/sale'
import Spinner from './Spinner'

const STEP_COPY: Record<(typeof TIMELINE)[number], { title: string; body: (sale: SaleState) => string }> = {
  [Phase.Bidding]: {
    title: 'Bidding',
    body: (sale) =>
      sale.keysReady
        ? `Bids are accepted until ${formatDateTime(sale.inputWindow[1])}.`
        : 'The committee makes one key for each round. This takes several minutes. Bids open when both keys exist.',
  },
  [Phase.Round1]: {
    title: 'Round 1',
    body: () => 'The program adds the round 1 ciphertexts. The committee decrypts the budget sums at a few price steps.',
  },
  [Phase.Probing]: {
    title: 'Probing',
    body: () => 'The contract reads the round 1 sums and picks the price steps to reveal next.',
  },
  [Phase.Round2]: {
    title: 'Round 2',
    body: () => 'The program adds the round 2 ciphertexts. The committee decrypts the sums at the new price steps.',
  },
  [Phase.Cleared]: {
    title: 'Cleared',
    body: () => 'The clearing price is public. Each bidder claims tokens and a refund to a fresh address.',
  },
}

/** The stages a sale passes through, with the current one marked. */
const PhaseTimeline: React.FC<{ sale: SaleState }> = ({ sale }) => {
  const { phase } = sale
  const stopped = isRefundPhase(phase)
  const current = timelineIndex(phase)

  return (
    <div className='space-y-5'>
      <ol className='steps'>
        {TIMELINE.map((step, index) => {
          const done = !stopped && (index < current || phase === Phase.Cleared)
          const active = !stopped && index === current && phase !== Phase.Cleared
          const state = done ? 'done' : active ? 'active' : 'todo'
          const copy = STEP_COPY[step]
          return (
            <li key={step} className={`step ${state}`}>
              <span className='pin'>{done ? <CheckCircleIcon size={16} weight='fill' /> : active ? <Spinner size={12} /> : index + 1}</span>
              <div>
                <p className={`font-semibold ${state === 'todo' ? '' : 'text-ink'}`}>{copy.title}</p>
                {(active || state === 'todo') && <p className='text-sm'>{copy.body(sale)}</p>}
                {active && phase === Phase.Clearable && (
                  <p className='text-sm'>Round 2 is decrypted. The sale clears with one more transaction. Anyone can send it.</p>
                )}
              </div>
            </li>
          )
        })}
      </ol>
      {stopped && (
        <div role='alert' className='note bad flex gap-3'>
          <XCircleIcon size={20} weight='fill' className='mt-0.5 shrink-0' />
          <p>
            <strong className='font-semibold'>{phase === Phase.Failed ? 'The sale failed.' : 'The sale stopped.'}</strong> {sale.stopReason}{' '}
            Bidders take their escrow back. The creator takes the supply back.
          </p>
        </div>
      )}
    </div>
  )
}

export default PhaseTimeline
