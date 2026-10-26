// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { Link } from 'react-router-dom'
import { type NegotiationState, ROLE_NAMES, formatLevel, phaseOf, roleOf, timeLeftLabel } from '@/utils/negotiation'
import { shorten } from '@/utils/error-formatting'
import StatusBadge from './StatusBadge'

const Fact: React.FC<{ label: string; children: React.ReactNode }> = ({ label, children }) => (
  <div className='min-w-0'>
    <dt className='mono-sm muted'>{label}</dt>
    <dd className='mt-1 text-sm'>{children}</dd>
  </div>
)

interface NegotiationCardProps {
  negotiation: NegotiationState
  now: bigint
  /** The connected account, to show its role. */
  account: string | undefined
}

const NegotiationCard: React.FC<NegotiationCardProps> = ({ negotiation, now, account }) => {
  const phase = phaseOf(negotiation, now)
  const role = roleOf(negotiation, account)
  return (
    <Link to={`/n/${negotiation.e3Id}`} className='card link flex h-full flex-col gap-5'>
      <div className='flex items-start justify-between gap-3'>
        <span className='mono muted'>Nº {negotiation.e3Id.toString().padStart(3, '0')}</span>
        <StatusBadge phase={phase} />
      </div>
      <div className='space-y-1'>
        <h3 className='h3'>{negotiation.title}</h3>
        <p className='muted text-sm'>
          {negotiation.levels} price levels · {formatLevel(negotiation, 0)} to {formatLevel(negotiation, negotiation.levels - 1)}
        </p>
      </div>
      <div className='hr-soft mt-auto' />
      <dl className='grid grid-cols-2 gap-3'>
        <Fact label='You are'>{role === null ? <span className='muted'>a viewer</span> : `the ${ROLE_NAMES[role]}`}</Fact>
        <Fact label='Time'>{timeLeftLabel(negotiation, phase, now)}</Fact>
        <Fact label='Seller'>
          <span className='addr'>{shorten(negotiation.seller, 6, 4)}</span>
        </Fact>
        <Fact label='Buyer'>
          <span className='addr'>{shorten(negotiation.buyer, 6, 4)}</span>
        </Fact>
      </dl>
    </Link>
  )
}

export const NegotiationCardSkeleton: React.FC = () => <div className='skeleton h-48' aria-hidden />

export default NegotiationCard
