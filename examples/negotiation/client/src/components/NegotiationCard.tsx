// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { Link } from 'react-router-dom'
import { type NegotiationState, ROLE_NAMES, formatLevel, phaseOf, roleOf, timeLeftLabel } from '@/utils/negotiation'
import { shorten } from '@/utils/error-formatting'
import { shortId } from '@/utils/format'
import StatusBadge from './StatusBadge'

interface NegotiationCardProps {
  negotiation: NegotiationState
  now: bigint
  /** The connected account, to show its role. */
  account: string | undefined
}

/** A negotiation as a row of the list: status and id, title, price range and parties, then role and time. */
const NegotiationCard: React.FC<NegotiationCardProps> = ({ negotiation, now, account }) => {
  const phase = phaseOf(negotiation, now)
  const role = roleOf(negotiation, account)
  return (
    <Link to={`/n/${negotiation.e3Id}`} className='list-row'>
      <div className='row-main space-y-2'>
        <div className='flex min-w-0 flex-wrap items-center gap-3'>
          <StatusBadge phase={phase} />
          <span className='id muted min-w-0 truncate' title={negotiation.e3Id.toString()}>
            Nº {shortId(negotiation.e3Id)}
          </span>
        </div>
        <h3 className='h3'>{negotiation.title}</h3>
        <p className='muted text-sm'>
          {negotiation.levels} price levels · {formatLevel(negotiation, 0)} to {formatLevel(negotiation, negotiation.levels - 1)}
        </p>
        <p className='muted text-sm'>
          Seller <span className='addr'>{shorten(negotiation.seller, 6, 4)}</span> · Buyer{' '}
          <span className='addr'>{shorten(negotiation.buyer, 6, 4)}</span>
        </p>
      </div>
      <div className='row-side'>
        <span className='meta text-ink'>{timeLeftLabel(negotiation, phase, now)}</span>
        <span className='meta muted'>{role === null ? 'Viewer' : `You are the ${ROLE_NAMES[role]}`}</span>
      </div>
    </Link>
  )
}

export const NegotiationCardSkeleton: React.FC = () => <div className='skeleton h-24' aria-hidden />

export default NegotiationCard
