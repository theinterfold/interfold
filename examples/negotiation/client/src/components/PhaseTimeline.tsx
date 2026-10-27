// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { CheckCircleIcon, XCircleIcon } from '@phosphor-icons/react'
import { FailureReason } from '@interfold/sdk'
import { type NegotiationPhase, type NegotiationState, PHASE_ORDER, formatDateTime, missingOffersText } from '@/utils/negotiation'
import Spinner from './Spinner'

const FAILURE_TEXT: Partial<Record<FailureReason, string>> = {
  [FailureReason.CommitteeFormationTimeout]: 'The committee did not form in time.',
  [FailureReason.InsufficientCommitteeMembers]: 'Too few ciphernodes joined the committee.',
  [FailureReason.DKGTimeout]: 'The committee did not finish generating its key in time.',
  [FailureReason.DKGInvalidShares]: 'The committee key generation produced invalid shares.',
  [FailureReason.NoInputsReceived]: 'No offers were received before the window closed.',
  [FailureReason.ComputeTimeout]: 'The computation did not finish in time. This happens when one party did not send its offer.',
  [FailureReason.ComputeProviderExpired]: 'The compute provider expired.',
  [FailureReason.ComputeProviderFailed]: 'The compute provider failed.',
  [FailureReason.RequesterCancelled]: 'The creator cancelled the negotiation.',
  [FailureReason.DecryptionTimeout]: 'The committee did not decrypt the result in time.',
  [FailureReason.DecryptionInvalidShares]: 'The decryption produced invalid shares.',
  [FailureReason.VerificationFailed]: 'The result failed verification.',
}

const STEP_COPY: Record<(typeof PHASE_ORDER)[number], { title: string; body: (negotiation: NegotiationState) => string }> = {
  'awaiting-key': {
    title: 'Key generation',
    body: () => 'The ciphernode committee generates the key that the offers are encrypted to. This takes several minutes.',
  },
  offers: {
    title: 'Offers open',
    body: (negotiation) => `The seller and the buyer each send one sealed offer until ${formatDateTime(negotiation.inputWindow[1])}.`,
  },
  computing: {
    title: 'Compute',
    body: () => 'The program combines the two encrypted offers without decrypting either of them.',
  },
  decrypting: {
    title: 'Decryption',
    body: () => 'The committee decrypts one ciphertext. It holds the match bit and the price, and nothing else.',
  },
  settled: {
    title: 'Settled',
    body: () => 'One transaction stores the result on chain: "No match" or the agreed price.',
  },
}

/** The stages a negotiation passes through, with the current one marked. */
const PhaseTimeline: React.FC<{ phase: NegotiationPhase; negotiation: NegotiationState }> = ({ phase, negotiation }) => {
  // `settling`: the output is public and one transaction is left, so the last step is the current one.
  // `incomplete`: the key and the offer window are done, and the compute does not start.
  const current = PHASE_ORDER.findIndex(
    (step) => step === (phase === 'settling' ? 'settled' : phase === 'incomplete' ? 'computing' : phase),
  )

  return (
    <div className='space-y-5'>
      <ol className='steps'>
        {PHASE_ORDER.map((step, index) => {
          const done = phase !== 'failed' && (index < current || phase === 'settled')
          const active = index === current && phase !== 'settled' && phase !== 'incomplete'
          const state = done ? 'done' : active ? 'active' : 'todo'
          const copy = STEP_COPY[step]
          return (
            <li key={step} className={`step ${state}`}>
              <span className='pin'>{done ? <CheckCircleIcon size={16} weight='fill' /> : active ? <Spinner size={12} /> : index + 1}</span>
              <div>
                <p className={`font-semibold ${state === 'todo' ? '' : 'text-ink'}`}>{copy.title}</p>
                {(active || state === 'todo') && <p className='text-sm'>{copy.body(negotiation)}</p>}
              </div>
            </li>
          )
        })}
      </ol>
      {phase === 'incomplete' && (
        <div role='alert' className='note bad flex gap-3'>
          <XCircleIcon size={20} weight='fill' className='mt-0.5 shrink-0' />
          <p>
            <strong className='font-semibold'>The offer window closed without both offers.</strong> {missingOffersText(negotiation.offered)}{' '}
            The program needs the two offers to compare them, so it does not run and there is no result.
          </p>
        </div>
      )}
      {phase === 'failed' && (
        <div role='alert' className='note bad flex gap-3'>
          <XCircleIcon size={20} weight='fill' className='mt-0.5 shrink-0' />
          <p>
            <strong className='font-semibold'>The negotiation failed.</strong>{' '}
            {negotiation.failureReason !== null && (FAILURE_TEXT[negotiation.failureReason] ?? FailureReason[negotiation.failureReason])}
          </p>
        </div>
      )}
    </div>
  )
}

export default PhaseTimeline
