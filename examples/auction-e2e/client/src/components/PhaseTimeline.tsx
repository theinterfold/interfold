// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { CheckCircleIcon, XCircleIcon } from '@phosphor-icons/react'
import {
  type AuctionPhase,
  type AuctionState,
  FAILURE_TEXT,
  PHASE_LABELS,
  PHASE_ORDER,
  STEP_TITLES,
  formatDateTime,
  maskCount,
  masksComplete,
} from '@/utils/auction'
import { KEY_GENERATION_HINT } from '@/utils/estimates'
import Spinner from './Spinner'

interface StepCopy {
  /** What the step does, shown while it is the current step or still to come. */
  body: (auction: AuctionState, phase: AuctionPhase, now: bigint) => string
  /** What the step did, shown once it is over. */
  done: (auction: AuctionState) => string
}

/** How old the key request is, in whole minutes, while the key is still awaited. Empty text when it is not known or not useful. */
function requestAge(auction: AuctionState, phase: AuctionPhase, now: bigint): string {
  if (phase !== 'awaiting-key') return ''
  const minutes = Number((now - auction.requestedAt) / 60n)
  return minutes >= 1 ? ` The request is ${minutes} ${minutes === 1 ? 'minute' : 'minutes'} old.` : ''
}

const STEP_COPY: Record<(typeof PHASE_ORDER)[number], StepCopy> = {
  'awaiting-key': {
    body: (auction, phase, now) =>
      `The ciphernode committee generates the key that bids are encrypted to. This takes ${KEY_GENERATION_HINT}.${requestAge(auction, phase, now)}`,
    done: () => 'The committee published the key that bids are encrypted to.',
  },
  bidding: {
    body: (auction) =>
      masksComplete(auction)
        ? `Bids are accepted until ${formatDateTime(auction.inputWindow[1])}.`
        : `Bids open when every mask provider has sent its mask (${maskCount(auction)}/${auction.providers.length} so far) and close at ${formatDateTime(auction.inputWindow[1])}.`,
    done: (auction) => `Bids were accepted until ${formatDateTime(auction.inputWindow[1])}.`,
  },
  computing: {
    body: () => 'The program compares the encrypted bids without decrypting any of them.',
    done: () => 'The program compared the encrypted bids without decrypting them.',
  },
  decrypting: {
    body: () => 'The committee decrypts one ciphertext: the outcome, nothing else.',
    done: () => 'The committee decrypted the outcome and nothing else.',
  },
  complete: {
    body: () => 'The winner and the price become public.',
    done: () => 'The winner and the price are public.',
  },
}

/**
 * The stages an auction passes through, with the current one marked. Titles come from `STEP_TITLES`.
 * Only the current phase label is announced to a screen reader. The text of the steps changes each minute and stays silent.
 */
const PhaseTimeline: React.FC<{ phase: AuctionPhase; auction: AuctionState; now: bigint }> = ({ phase, auction, now }) => {
  const current = PHASE_ORDER.findIndex((step) => step === phase)

  return (
    <div className='space-y-5'>
      <p className='sr-only' role='status'>
        {PHASE_LABELS[phase]}
      </p>
      <ol className='steps'>
        {PHASE_ORDER.map((step, index) => {
          const done = phase !== 'failed' && (index < current || phase === 'complete')
          const active = index === current && phase !== 'complete'
          const state = done ? 'done' : active ? 'active' : 'todo'
          const copy = STEP_COPY[step]
          return (
            <li key={step} className={`step ${state}`}>
              <span className='pin'>{done ? <CheckCircleIcon size={16} weight='fill' /> : active ? <Spinner size={12} /> : index + 1}</span>
              <div>
                <p className={`font-semibold ${state === 'todo' ? '' : 'text-ink'}`}>{STEP_TITLES[step]}</p>
                <p className='text-sm'>{done ? copy.done(auction) : copy.body(auction, phase, now)}</p>
              </div>
            </li>
          )
        })}
      </ol>
      {phase === 'failed' && (
        <div role='alert' className='note bad flex gap-3'>
          <XCircleIcon size={20} weight='fill' className='mt-0.5 shrink-0' />
          <p>
            <strong className='font-semibold'>The auction failed.</strong>{' '}
            {auction.failureReason !== null && FAILURE_TEXT[auction.failureReason]}
          </p>
        </div>
      )}
    </div>
  )
}

export default PhaseTimeline
