// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { CheckCircleIcon, XCircleIcon } from '@phosphor-icons/react'
import { FailureReason } from '@interfold/sdk'
import { type SalePhase, type SaleState, PHASE_ORDER, formatDateTime } from '@/utils/sale'
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
  [FailureReason.RequesterCancelled]: 'The creator cancelled the round.',
  [FailureReason.DecryptionTimeout]: 'The committee did not decrypt the result in time.',
  [FailureReason.DecryptionInvalidShares]: 'The decryption produced invalid shares.',
  [FailureReason.VerificationFailed]: 'The result failed verification.',
}

const STEP_COPY: Record<(typeof PHASE_ORDER)[number], { title: string; body: (sale: SaleState) => string }> = {
  'awaiting-key': {
    title: 'Committee key',
    body: () => 'The ciphernode committee generates the key that bids are encrypted to. This takes several minutes.',
  },
  bidding: {
    title: 'Bidding open',
    body: (sale) => `Bids are accepted until ${formatDateTime(sale.inputWindow[1])}.`,
  },
  computing: {
    title: 'Computing',
    body: () => 'The program combines the encrypted bids and the random masks without decrypting any of them.',
  },
  decrypting: {
    title: 'Decrypting',
    body: () =>
      'The committee decrypts one ciphertext. It shows the outcome, the clearing step and which bids counted. It shows no demand curve.',
  },
  complete: {
    title: 'Round decided',
    body: () =>
      'The outcome is public. Bidders above the clearing step claim first, bidders at the step register next, and everyone else is refunded.',
  },
}

/** The stages a sale passes through, with the current one marked. */
const PhaseTimeline: React.FC<{ phase: SalePhase; sale: SaleState }> = ({ phase, sale }) => {
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
                {(active || state === 'todo') && <p className='text-sm'>{copy.body(sale)}</p>}
              </div>
            </li>
          )
        })}
      </ol>
      {phase === 'failed' && (
        <div role='alert' className='note bad flex gap-3'>
          <XCircleIcon size={20} weight='fill' className='mt-0.5 shrink-0' />
          <p>
            <strong className='font-semibold'>The round failed.</strong>{' '}
            {sale.failureReason !== null && (FAILURE_TEXT[sale.failureReason] ?? FailureReason[sale.failureReason])}
          </p>
        </div>
      )}
    </div>
  )
}

export default PhaseTimeline
