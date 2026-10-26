// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { formatUnits } from 'viem'
import { type ClearingInfo, type SaleState, formatPriceValue, formatStepPrice } from '@/utils/sale'
import { formatAmount } from '@/utils/tokens'

const WIDTH = 720
const HEIGHT = 320
const MARGIN = { top: 28, right: 20, bottom: 52, left: 64 }

/** Payment-token base units as a plain number, enough to draw. */
const toNumber = (amount: bigint, decimals: number) => Number(formatUnits(amount, decimals))

interface Props {
  sale: SaleState
  /** `F[l]` in budget units for each step; `null` where the committee did not reveal the level. */
  sums: readonly (bigint | null)[]
  /** The clearing, once the contract has computed it. */
  clearing: ClearingInfo | null
  /** The max price step of the viewer's own bid, if this browser knows it. */
  myStep: number | null
}

/**
 * The partial demand curve. A solid bar is a revealed budget sum at a price step: the budgets of all
 * bids with a max price step at or above it. A hollow dashed mark is a step that the probe search did
 * not reveal. The line is the payment that buys the whole supply at each price: where a bar is above
 * the line, the demand at that price is above the supply.
 */
const ProbeChart: React.FC<Props> = ({ sale, sums, clearing, myStep }) => {
  const { levels, prices, supply, budgetUnit, paymentToken, saleToken } = sale
  const saleUnit = 10n ** BigInt(saleToken.decimals)
  const demand = sums.map((sum) => (sum === null ? null : toNumber(sum * budgetUnit, paymentToken.decimals)))
  const needed = prices.map((price) => toNumber((price * supply) / saleUnit, paymentToken.decimals))
  const top = Math.max(...needed, ...demand.map((value) => value ?? 0)) * 1.12 || 1
  const plotW = WIDTH - MARGIN.left - MARGIN.right
  const plotH = HEIGHT - MARGIN.top - MARGIN.bottom
  const band = plotW / levels
  const x = (level: number) => MARGIN.left + band * (level + 0.5)
  const y = (value: number) => MARGIN.top + plotH * (1 - value / top)
  const ticks = [0, 0.25, 0.5, 0.75, 1].map((fraction) => top * fraction)
  const linePoints = needed.map((value, level) => `${x(level)},${y(value)}`).join(' ')
  const clearingX = clearing ? x(clearing.kind === 'undersubscribed' ? 0 : clearing.step) : null

  return (
    <figure className='space-y-3'>
      <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} role='img' aria-label='Partial demand curve' className='w-full'>
        {ticks.map((tick) => (
          <g key={tick}>
            <line x1={MARGIN.left} x2={WIDTH - MARGIN.right} y1={y(tick)} y2={y(tick)} stroke='var(--rule)' />
            <text x={MARGIN.left - 8} y={y(tick) + 4} textAnchor='end' className='fill-ink-soft font-mono' fontSize={10}>
              {formatAmount(BigInt(Math.round(tick * 10 ** Math.min(paymentToken.decimals, 6))), Math.min(paymentToken.decimals, 6), 2)}
            </text>
          </g>
        ))}
        {demand.map((value, level) => (
          <g key={level}>
            {value === null ? (
              <g>
                <rect
                  x={x(level) - band * 0.34}
                  y={y(0) - 14}
                  width={band * 0.68}
                  height={14}
                  fill='none'
                  stroke='var(--ink-soft)'
                  strokeDasharray='3 3'
                >
                  <title>{`Step ${level}: not revealed.`}</title>
                </rect>
                <text x={x(level)} y={y(0) - 4} textAnchor='middle' className='fill-ink-soft font-mono' fontSize={10}>
                  ?
                </text>
              </g>
            ) : (
              <g>
                <rect
                  x={x(level) - band * 0.34}
                  y={y(value)}
                  width={band * 0.68}
                  height={Math.max(y(0) - y(value), 0)}
                  fill='var(--accent)'
                  stroke='var(--accent)'
                >
                  <title>{`Step ${level}: price ${formatStepPrice(sale, level)} ${paymentToken.symbol}. Budgets at or above this step: ${formatAmount((sums[level] ?? 0n) * budgetUnit, paymentToken.decimals)} ${paymentToken.symbol}.`}</title>
                </rect>
                <text x={x(level)} y={y(value) - 6} textAnchor='middle' className='fill-ink font-mono' fontSize={11}>
                  {sums[level]?.toString()}
                </text>
              </g>
            )}
            <text x={x(level)} y={HEIGHT - MARGIN.bottom + 16} textAnchor='middle' className='fill-ink-soft font-mono' fontSize={10}>
              {formatStepPrice(sale, level)}
            </text>
            {myStep === level && (
              <text x={x(level)} y={HEIGHT - MARGIN.bottom + 32} textAnchor='middle' className='fill-warm font-mono' fontSize={10}>
                ▲ you
              </text>
            )}
          </g>
        ))}
        <polyline points={linePoints} fill='none' stroke='var(--danger)' strokeWidth={1.5} strokeDasharray='6 4' />
        <text
          x={WIDTH - MARGIN.right}
          y={Math.max(y(needed[levels - 1]) - 6, 10)}
          textAnchor='end'
          className='fill-danger font-mono'
          fontSize={10}
        >
          payment for the whole supply
        </text>
        {clearingX !== null && clearing && (
          <g>
            <line x1={clearingX} x2={clearingX} y1={MARGIN.top - 8} y2={y(0)} stroke='var(--warm)' strokeWidth={2} />
            <text x={clearingX} y={MARGIN.top - 12} textAnchor='middle' className='fill-warm font-mono' fontSize={10}>
              clears at {formatPriceValue(sale, clearing.pStar)}
            </text>
          </g>
        )}
        <text x={MARGIN.left + plotW / 2} y={HEIGHT - 6} textAnchor='middle' className='fill-ink-soft font-mono' fontSize={10}>
          price step ({paymentToken.symbol} per {saleToken.symbol})
        </text>
        <text
          transform={`translate(14 ${MARGIN.top + plotH / 2}) rotate(-90)`}
          textAnchor='middle'
          className='fill-ink-soft font-mono'
          fontSize={10}
        >
          {paymentToken.symbol} of budget
        </text>
      </svg>
      <figcaption className='muted text-xs'>
        A solid bar is a budget sum that the committee revealed. The number above it is the sum in budget units. A dashed mark is a price
        step that the committee did not reveal. The dashed line is the payment that buys the whole supply at each price.
      </figcaption>
    </figure>
  )
}

export default ProbeChart
