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
import { formatAmount } from '@/utils/tokens'
import StatusBadge from './StatusBadge'

const Fact: React.FC<{ label: string; children: React.ReactNode }> = ({ label, children }) => (
  <div className='min-w-0'>
    <dt className='mono-sm muted'>{label}</dt>
    <dd className='mt-1 text-sm'>{children}</dd>
  </div>
)

const SaleCard: React.FC<{ sale: SaleState; now: bigint }> = ({ sale, now }) => {
  const phase = phaseOf(sale, now)
  return (
    <Link to={`/sale/${sale.e3Id}`} className='card link flex h-full flex-col gap-5'>
      <div className='flex items-start justify-between gap-3'>
        <span className='mono muted'>Nº {sale.e3Id.toString().padStart(3, '0')}</span>
        <StatusBadge phase={phase} />
      </div>
      <div className='space-y-1'>
        <h3 className='h3'>{sale.title}</h3>
        <p className='muted text-sm'>
          {formatAmount(sale.supply, sale.saleToken.decimals)} {sale.saleToken.symbol} · {sale.prices.length} price steps
        </p>
      </div>
      <div className='hr-soft mt-auto' />
      <dl className='grid grid-cols-3 gap-3'>
        <Fact label='Bidders'>
          <span className='font-mono text-xs'>
            {sale.bidderCount}/{MAX_BIDDERS}
          </span>
        </Fact>
        <Fact label='Time'>{timeLeftLabel(sale, phase, now)}</Fact>
        <Fact label='By'>
          <span className='addr'>{shorten(sale.creator, 6, 4)}</span>
        </Fact>
      </dl>
    </Link>
  )
}

export const SaleCardSkeleton: React.FC = () => <div className='skeleton h-48' aria-hidden />

export default SaleCard
