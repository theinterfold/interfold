// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { CheckCircleIcon, XCircleIcon } from '@phosphor-icons/react'
import { FailureReason } from '@interfold/sdk'
import { type AuctionPhase, type AuctionState, PHASE_ORDER, formatDateTime } from '@/utils/auction'
import Spinner from './Spinner'

const FAILURE_TEXT: Partial<Record<FailureReason, string>> = {
  [FailureReason.CommitteeFormationTimeout]: 'The committee did not form in time.',
  [FailureReason.InsufficientCommitteeMembers]: 'Too few ciphernodes joined the committee.',
  [FailureReason.DKGTimeout]: 'The committee did not finish generating its key in time.',
  [FailureReason.DKGInvalidShares]: 'The committee key generation produced invalid shares.',
  [FailureReason.NoInputsReceived]: 'No bids were received before the window closed.',
  [FailureReason.ComputeTimeout]: 'The computation did not finish in time.',
  [FailureReason.ComputeProviderExpired]: 'The compute provider expired.',
  [FailureReason.ComputeProviderFailed]: 'The compute provider failed.',
  [FailureReason.RequesterCancelled]: 'The creator cancelled the auction.',
  [FailureReason.DecryptionTimeout]: 'The committee did not decrypt the result in time.',
  [FailureReason.DecryptionInvalidShares]: 'The decryption produced invalid shares.',
  [FailureReason.VerificationFailed]: 'The result failed verification.',
}

const STEP_COPY: Record<(typeof PHASE_ORDER)[number], { title: string; body: (auction: AuctionState) => string }> = {
  'awaiting-key': {
    title: 'Committee key',
    body: () => 'The ciphernode committee generates the key that bids are encrypted to. This takes several minutes.',
  },
  bidding: {
    title: 'Bidding open',
    body: (auction) => `Bids are accepted until ${formatDateTime(auction.inputWindow[1])}.`,
  },
  computing: {
    title: 'Computing',
    body: () => 'The program compares the encrypted bids without decrypting any of them.',
  },
  decrypting: {
    title: 'Decrypting',
    body: () => 'The committee decrypts one ciphertext: the outcome, nothing else.',
  },
  complete: {
    title: 'Result',
    body: () => 'The winner and the price are public.',
  },
}

/** The stages an auction passes through, with the current one marked. */
const PhaseTimeline: React.FC<{ phase: AuctionPhase; auction: AuctionState }> = ({ phase, auction }) => {
  const current = PHASE_ORDER.findIndex((step) => step === phase)

  return (
    <div className='space-y-5'>
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
                <p className={`font-semibold ${state === 'todo' ? '' : 'text-ink'}`}>{copy.title}</p>
                {(active || state === 'todo') && <p className='text-sm'>{copy.body(auction)}</p>}
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
            {auction.failureReason !== null && (FAILURE_TEXT[auction.failureReason] ?? FailureReason[auction.failureReason])}
          </p>
        </div>
      )}
    </div>
  )
}

export default PhaseTimeline
