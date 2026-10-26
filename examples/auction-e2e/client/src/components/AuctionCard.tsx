// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { Link } from 'react-router-dom'
import { AUCTION_TYPE_LABELS, MAX_BIDDERS_BY_TYPE } from '@interfold/auction'
import { type AuctionState, phaseOf, timeLeftLabel } from '@/utils/auction'
import { shorten } from '@/utils/error-formatting'
import { shortId } from '@/utils/format'
import StatusBadge from './StatusBadge'
import { PictureThumb } from './AuctionPicture'

export const Pips: React.FC<{ filled: number; total: number }> = ({ filled, total }) => (
  <span className='pips' aria-hidden>
    {Array.from({ length: total }, (_, index) => (
      <i key={index} className={index < filled ? 'on' : ''} />
    ))}
  </span>
)

/** An auction as a row of the list: status and id, title, type and creator, then time and bidders. */
const AuctionCard: React.FC<{ auction: AuctionState; now: bigint }> = ({ auction, now }) => {
  const phase = phaseOf(auction, now)
  const maxBidders = MAX_BIDDERS_BY_TYPE[auction.auctionType]
  return (
    <Link to={`/auction/${auction.e3Id}`} className='list-row'>
      <div className='row-main flex items-start gap-4'>
        <PictureThumb e3Id={auction.e3Id} />
        <div className='min-w-0 space-y-2'>
          <div className='flex min-w-0 flex-wrap items-center gap-3'>
            <StatusBadge phase={phase} />
            <span className='id muted min-w-0 truncate' title={auction.e3Id.toString()}>
              Nº {shortId(auction.e3Id)}
            </span>
          </div>
          <h3 className='h3'>{auction.title}</h3>
          <p className='muted text-sm'>
            {AUCTION_TYPE_LABELS[auction.auctionType]} · {auction.prices.length} steps · by{' '}
            <span className='addr'>{shorten(auction.creator, 6, 4)}</span>
          </p>
        </div>
      </div>
      <div className='row-side'>
        <span className='meta text-ink'>{timeLeftLabel(auction, phase, now)}</span>
        <span className='flex items-center gap-2'>
          <Pips filled={auction.bidderCount} total={maxBidders} />
          <span className='font-mono text-xs text-muted'>
            {auction.bidderCount}/{maxBidders}
          </span>
        </span>
      </div>
    </Link>
  )
}

export const AuctionCardSkeleton: React.FC = () => <div className='skeleton h-24' aria-hidden />

export default AuctionCard
