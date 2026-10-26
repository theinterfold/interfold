// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { Link } from 'react-router-dom'
import { MAX_BIDDERS } from '@interfold/token-launch'
import { type SaleState, formatStepPrice, timeLeftLabel } from '@/utils/sale'
import { shorten } from '@/utils/error-formatting'
import { formatAmount } from '@/utils/tokens'
import StatusBadge from './StatusBadge'

const Fact: React.FC<{ label: string; children: React.ReactNode }> = ({ label, children }) => (
  <div className='min-w-0'>
    <dt className='mono-sm muted'>{label}</dt>
    <dd className='mt-1 text-sm'>{children}</dd>
  </div>
)

const SaleCard: React.FC<{ sale: SaleState; now: bigint }> = ({ sale, now }) => (
  <Link to={`/sale/${sale.saleId}`} className='card link flex h-full flex-col gap-5'>
    <div className='flex items-start justify-between gap-3'>
      <span className='mono muted'>Nº {sale.saleId.toString().padStart(3, '0')}</span>
      <StatusBadge phase={sale.phase} waitingForKeys={!sale.keysReady} />
    </div>
    <div className='space-y-1'>
      <h3 className='h3'>{sale.title}</h3>
      <p className='muted text-sm'>
        {formatAmount(sale.supply, sale.saleToken.decimals)} {sale.saleToken.symbol} · {formatStepPrice(sale, 0)} to{' '}
        {formatStepPrice(sale, sale.levels - 1)} {sale.paymentToken.symbol}
      </p>
    </div>
    <div className='hr-soft mt-auto' />
    <dl className='grid grid-cols-3 gap-3'>
      <Fact label='Bids'>
        <span className='font-mono text-xs'>
          {sale.bidCount}/{MAX_BIDDERS}
        </span>
      </Fact>
      <Fact label='Time'>{timeLeftLabel(sale, now)}</Fact>
      <Fact label='By'>
        <span className='addr'>{shorten(sale.creator, 6, 4)}</span>
      </Fact>
    </dl>
  </Link>
)

export const SaleCardSkeleton: React.FC = () => <div className='skeleton h-48' aria-hidden />

export default SaleCard
