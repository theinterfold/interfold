// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import type { Clearing } from '@/hooks/useClearing'
import { type SaleState, formatPriceValue, formatSaleTokens, formatStepPrice } from '@/utils/sale'
import { formatAmount } from '@/utils/tokens'

const WIDTH = 720
const HEIGHT = 320
const MARGIN = { top: 28, right: 20, bottom: 52, left: 64 }

/** The demand of the bidders at each step in whole sale tokens: `c_l * E / p_l`. A `number` is exact enough to draw. */
export function demandAt(sale: SaleState, counts: readonly bigint[], level: number): number {
  const unit = 10n ** BigInt(sale.saleToken.decimals)
  // Fixed point with 6 decimals keeps the division of the bigints exact enough for a chart.
  const scaled = (counts[level] * sale.escrow * unit * 1_000_000n) / sale.prices[level]
  return Number(scaled) / 1_000_000 / Number(unit)
}

interface Props {
  sale: SaleState
  /** `c_l` for each step of the sale. */
  counts: readonly bigint[]
  /** The clearing, once the contract has computed it. */
  clearing: Clearing | null
  /** The step of the bid of the viewer, if its browser knows it. */
  myLevel: number | null
}

/**
 * The demand curve: the sale tokens the bidders want at each price step, against the supply. The sale
 * clears where the curve meets the supply line. Bars show the demand at a step; the number above a bar
 * is the count of bidders at or above that step.
 */
const DemandChart: React.FC<Props> = ({ sale, counts, clearing, myLevel }) => {
  const levels = sale.prices.length
  const demand = Array.from({ length: levels }, (_, level) => demandAt(sale, counts, level))
  const supply = Number(sale.supply) / 10 ** sale.saleToken.decimals
  const top = Math.max(supply, ...demand) * 1.12 || 1
  const plotW = WIDTH - MARGIN.left - MARGIN.right
  const plotH = HEIGHT - MARGIN.top - MARGIN.bottom
  const band = plotW / levels
  const x = (level: number) => MARGIN.left + band * (level + 0.5)
  const y = (value: number) => MARGIN.top + plotH * (1 - value / top)
  const ticks = [0, 0.25, 0.5, 0.75, 1].map((fraction) => top * fraction)

  // The clearing price marker sits between two steps when the sale is uncapped.
  let priceX: number | null = null
  if (clearing) {
    if (clearing.kind === 'uncapped' && clearing.step > 0) {
      const below = sale.prices[clearing.step - 1]
      const above = sale.prices[clearing.step]
      const fraction = Number(((clearing.pStar - below) * 10_000n) / (above - below)) / 10_000
      priceX = x(clearing.step - 1) + fraction * band
    } else {
      priceX = x(clearing.kind === 'undersubscribed' ? 0 : clearing.step)
    }
  }
  // The steps at or above the clearing price are the ones whose bidders are active at it.
  const filled = (level: number) => clearing !== null && (clearing.kind === 'undersubscribed' || level >= clearing.step)

  return (
    <figure className='space-y-3'>
      <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} role='img' aria-label='Demand curve' className='w-full'>
        {ticks.map((tick) => (
          <g key={tick}>
            <line x1={MARGIN.left} x2={WIDTH - MARGIN.right} y1={y(tick)} y2={y(tick)} stroke='var(--rule)' />
            <text x={MARGIN.left - 8} y={y(tick) + 4} textAnchor='end' className='fill-ink-soft font-mono' fontSize={10}>
              {formatAmount(BigInt(Math.round(tick)), 0)}
            </text>
          </g>
        ))}
        {demand.map((value, level) => (
          <g key={level}>
            <rect
              x={x(level) - band * 0.34}
              y={y(value)}
              width={band * 0.68}
              height={Math.max(y(0) - y(value), 0)}
              fill={filled(level) ? 'var(--accent)' : 'var(--accent-tint)'}
              stroke='var(--accent)'
            >
              <title>
                {`Step ${level}: price ${formatStepPrice(sale, level)} ${sale.paymentToken.symbol}. ${counts[level]} bidders want ${formatSaleTokens(sale, BigInt(Math.round(value * 10 ** sale.saleToken.decimals)))}`}
              </title>
            </rect>
            <text x={x(level)} y={y(value) - 6} textAnchor='middle' className='fill-ink font-mono' fontSize={11}>
              {counts[level].toString()}
            </text>
            <text x={x(level)} y={HEIGHT - MARGIN.bottom + 16} textAnchor='middle' className='fill-ink-soft font-mono' fontSize={10}>
              {formatStepPrice(sale, level)}
            </text>
            {myLevel === level && (
              <text x={x(level)} y={HEIGHT - MARGIN.bottom + 32} textAnchor='middle' className='fill-warm font-mono' fontSize={10}>
                ▲ you
              </text>
            )}
          </g>
        ))}
        <line
          x1={MARGIN.left}
          x2={WIDTH - MARGIN.right}
          y1={y(supply)}
          y2={y(supply)}
          stroke='var(--danger)'
          strokeWidth={1.5}
          strokeDasharray='6 4'
        />
        <text x={WIDTH - MARGIN.right} y={y(supply) - 6} textAnchor='end' className='fill-danger font-mono' fontSize={10}>
          supply {formatAmount(sale.supply, sale.saleToken.decimals)}
        </text>
        {priceX !== null && clearing && (
          <g>
            <line x1={priceX} x2={priceX} y1={MARGIN.top - 8} y2={y(0)} stroke='var(--warm)' strokeWidth={2} />
            <text x={priceX} y={MARGIN.top - 12} textAnchor='middle' className='fill-warm font-mono' fontSize={10}>
              clears at {formatPriceValue(sale, clearing.pStar)}
            </text>
          </g>
        )}
        <text x={MARGIN.left + plotW / 2} y={HEIGHT - 6} textAnchor='middle' className='fill-ink-soft font-mono' fontSize={10}>
          price step ({sale.paymentToken.symbol} per {sale.saleToken.symbol})
        </text>
        <text
          transform={`translate(14 ${MARGIN.top + plotH / 2}) rotate(-90)`}
          textAnchor='middle'
          className='fill-ink-soft font-mono'
          fontSize={10}
        >
          {sale.saleToken.symbol} wanted
        </text>
      </svg>
      <figcaption className='muted text-xs'>
        A bar is the number of {sale.saleToken.symbol} that the bidders at or above that price step want, if they each spend their escrow at
        that price. The number above it is how many bidders that is. The dashed line is the supply.
      </figcaption>
    </figure>
  )
}

export default DemandChart
