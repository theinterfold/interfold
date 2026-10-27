// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { Link } from 'react-router-dom'
import { MAX_BIDDERS } from '@interfold/sealed-cca'
import { type SaleState, phaseOf, timeLeftLabel } from '@/utils/sale'
import { shorten } from '@/utils/error-formatting'
import { shortId } from '@/utils/format'
import { formatAmount } from '@/utils/tokens'
import StatusBadge from './StatusBadge'

/** A sale as a row of the list: status and id, title, supply and creator, then time and bidders. */
const SaleCard: React.FC<{ sale: SaleState; now: bigint }> = ({ sale, now }) => {
  const phase = phaseOf(sale, now)
  return (
    <Link to={`/sale/${sale.e3Id}`} className='list-row'>
      <div className='row-main space-y-2'>
        <div className='flex min-w-0 flex-wrap items-center gap-3'>
          <StatusBadge phase={phase} />
          <span className='id muted min-w-0 truncate' title={sale.e3Id.toString()}>
            {shortId(sale.e3Id)}
          </span>
        </div>
        <h3 className='h3'>{sale.title}</h3>
        <p className='muted text-sm'>
          {formatAmount(sale.supply, sale.saleToken.decimals)} {sale.saleToken.symbol} · {sale.prices.length} price steps · by{' '}
          <span className='addr'>{shorten(sale.creator, 6, 4)}</span>
        </p>
      </div>
      <div className='row-side'>
        <span className='meta text-ink'>{timeLeftLabel(sale, phase, now)}</span>
        <span className='font-mono text-xs text-muted'>
          {sale.bidderCount}/{MAX_BIDDERS} bidders
        </span>
      </div>
    </Link>
  )
}

export const SaleCardSkeleton: React.FC = () => <div className='skeleton h-24' aria-hidden />

export default SaleCard
