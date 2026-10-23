// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { Link } from 'react-router-dom'
import { AUCTION_TYPE_LABELS, MAX_BIDDERS_BY_TYPE } from '@shared/layout'
import { type AuctionState, phaseOf, timeLeftLabel } from '@/utils/auction'
import { shorten } from '@/utils/error-formatting'
import StatusBadge from './StatusBadge'

const Fact: React.FC<{ label: string; children: React.ReactNode }> = ({ label, children }) => (
  <div className='min-w-0'>
    <dt className='mono-sm muted'>{label}</dt>
    <dd className='mt-1 text-sm'>{children}</dd>
  </div>
)

export const Pips: React.FC<{ filled: number; total: number }> = ({ filled, total }) => (
  <span className='pips' aria-hidden>
    {Array.from({ length: total }, (_, index) => (
      <i key={index} className={index < filled ? 'on' : ''} />
    ))}
  </span>
)

const AuctionCard: React.FC<{ auction: AuctionState; now: bigint }> = ({ auction, now }) => {
  const phase = phaseOf(auction, now)
  const maxBidders = MAX_BIDDERS_BY_TYPE[auction.auctionType]
  return (
    <Link to={`/auction/${auction.e3Id}`} className='card link flex h-full flex-col gap-5'>
      <div className='flex items-start justify-between gap-3'>
        <span className='mono muted'>Nº {auction.e3Id.toString().padStart(3, '0')}</span>
        <StatusBadge phase={phase} />
      </div>
      <div className='space-y-1'>
        <h3 className='h3'>{auction.title}</h3>
        <p className='muted text-sm'>
          {AUCTION_TYPE_LABELS[auction.auctionType]} · {auction.prices.length} steps
        </p>
      </div>
      <div className='hr-soft mt-auto' />
      <dl className='grid grid-cols-3 gap-3'>
        <Fact label='Bidders'>
          <span className='flex items-center gap-2'>
            <Pips filled={auction.bidderCount} total={maxBidders} />
            <span className='font-mono text-xs'>
              {auction.bidderCount}/{maxBidders}
            </span>
          </span>
        </Fact>
        <Fact label='Time'>{timeLeftLabel(auction, phase, now)}</Fact>
        <Fact label='By'>
          <span className='addr'>{shorten(auction.creator, 6, 4)}</span>
        </Fact>
      </dl>
    </Link>
  )
}

export const AuctionCardSkeleton: React.FC = () => <div className='skeleton h-48' aria-hidden />

export default AuctionCard
