// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useMemo, useState } from 'react'
import { designNames, type Profile } from '@designs'
import { designStyles } from '../lib/designInfo'
import { MAX_BIDDERS, MIN_BIDDERS, measureCost } from '../lib/simulate'

const BIDDER_COUNTS = Array.from({ length: MAX_BIDDERS - MIN_BIDDERS + 1 }, (_, i) => MIN_BIDDERS + i)

const WIDTH = 520
const HEIGHT = 260
const MARGIN = { top: 14, right: 16, bottom: 34, left: 40 }

interface Series {
  design: string
  /** One value for each bidder count. `null` where the profile cannot hold the auction. */
  values: (number | null)[]
}

interface LineChartProps {
  title: string
  series: Series[]
  currentBidders: number
  highlight: string | null
  /** Distance between two y ticks. */
  tickStep: number
}

function LineChart({ title, series, currentBidders, highlight, tickStep }: LineChartProps) {
  const top = Math.max(1, ...series.flatMap((s) => s.values.filter((value): value is number => value !== null)))
  const yMax = Math.ceil(top / tickStep) * tickStep
  const plotWidth = WIDTH - MARGIN.left - MARGIN.right
  const plotHeight = HEIGHT - MARGIN.top - MARGIN.bottom
  const x = (bidders: number) => MARGIN.left + ((bidders - MIN_BIDDERS) / (MAX_BIDDERS - MIN_BIDDERS)) * plotWidth
  const y = (value: number) => MARGIN.top + plotHeight - (value / yMax) * plotHeight
  const ticks = Array.from({ length: yMax / tickStep + 1 }, (_, i) => i * tickStep)

  return (
    <figure className='m-0 flex min-w-0 flex-col gap-2'>
      <figcaption className='mono-sm text-ink-soft'>{title}</figcaption>
      <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} className='w-full' role='img' aria-label={title}>
        {ticks.map((tick) => (
          <g key={tick}>
            <line x1={MARGIN.left} x2={WIDTH - MARGIN.right} y1={y(tick)} y2={y(tick)} stroke='var(--rule)' />
            <text x={MARGIN.left - 8} y={y(tick) + 3} textAnchor='end' fontSize='10' fontFamily='var(--f-mono)' fill='var(--ink-soft)'>
              {tick}
            </text>
          </g>
        ))}
        {BIDDER_COUNTS.map((bidders) => (
          <text
            key={bidders}
            x={x(bidders)}
            y={HEIGHT - MARGIN.bottom + 16}
            textAnchor='middle'
            fontSize='10'
            fontFamily='var(--f-mono)'
            fill='var(--ink-soft)'
          >
            {bidders}
          </text>
        ))}
        <text
          x={MARGIN.left + plotWidth / 2}
          y={HEIGHT - 4}
          textAnchor='middle'
          fontSize='10'
          fontFamily='var(--f-mono)'
          fill='var(--ink-soft)'
        >
          bidders n
        </text>
        <line
          x1={x(currentBidders)}
          x2={x(currentBidders)}
          y1={MARGIN.top}
          y2={MARGIN.top + plotHeight}
          stroke='var(--accent)'
          strokeWidth='1'
          strokeDasharray='2 3'
        />
        {series.map(({ design, values }) => {
          const style = designStyles[design]
          const dimmed = highlight !== null && highlight !== design
          const segments: string[] = []
          values.forEach((value, i) => {
            if (value === null) return
            const command = i > 0 && values[i - 1] !== null ? 'L' : 'M'
            segments.push(`${command}${x(BIDDER_COUNTS[i])},${y(value)}`)
          })
          return (
            <g key={design} opacity={dimmed ? 0.15 : 1}>
              <path
                d={segments.join(' ')}
                fill='none'
                stroke={style.color}
                strokeWidth={highlight === design ? 3 : 1.75}
                strokeDasharray={style.dash}
              />
              {values.map((value, i) =>
                value === null ? null : (
                  <circle key={i} cx={x(BIDDER_COUNTS[i])} cy={y(value)} r='3' fill={style.color}>
                    <title>{`${design}, n = ${BIDDER_COUNTS[i]}: ${value}`}</title>
                  </circle>
                ),
              )}
            </g>
          )
        })}
      </svg>
    </figure>
  )
}

interface CostChartProps {
  profile: Profile
  levels: number
  bidders: number
}

/** ct×ct and depth of every design for 2 to 16 bidders. The demo profile asks first. */
export function CostChart({ profile, levels, bidders }: CostChartProps) {
  const [approved, setApproved] = useState<string | null>(null)
  const key = `${profile}|${levels}`
  const ready = profile === 'toy' || approved === key
  const [highlight, setHighlight] = useState<string | null>(null)

  const data = useMemo(() => {
    if (!ready) return null
    const costs = designNames.map((design) => ({
      design,
      costs: BIDDER_COUNTS.map((count) => measureCost(design, profile, count, levels)),
    }))
    const pick = (field: 'ciphertextProducts' | 'depth'): Series[] =>
      costs.map(({ design, costs: row }) => ({ design, values: row.map((outcome) => (outcome.ok ? outcome.cost[field] : null)) }))
    return { products: pick('ciphertextProducts'), depth: pick('depth') }
  }, [ready, profile, levels])

  if (data === null) {
    return (
      <div className='card flat flex flex-col items-start gap-3'>
        <p className='m-0 text-ink-2'>
          The demo profile has N = 16384 slots. Measuring 10 designs for 15 bidder counts takes about 10 seconds.
        </p>
        <button type='button' className='btn accent sm' onClick={() => setApproved(key)}>
          Measure on the demo profile
        </button>
      </div>
    )
  }

  return (
    <div className='card flat flex flex-col gap-5'>
      <div className='grid gap-6 md:grid-cols-2'>
        <LineChart title='ct×ct products' series={data.products} currentBidders={bidders} highlight={highlight} tickStep={10} />
        <LineChart title='Multiplicative depth' series={data.depth} currentBidders={bidders} highlight={highlight} tickStep={1} />
      </div>
      <div className='flex flex-wrap gap-x-5 gap-y-2' onMouseLeave={() => setHighlight(null)}>
        {designNames.map((design) => {
          const style = designStyles[design]
          return (
            <button
              key={design}
              type='button'
              className='inline-flex items-center gap-2 border-0 bg-transparent p-0 font-mono text-[11px] text-ink-2'
              onMouseEnter={() => setHighlight(design)}
              onFocus={() => setHighlight(design)}
              onBlur={() => setHighlight(null)}
            >
              <svg width='28' height='8' aria-hidden>
                <line x1='0' x2='28' y1='4' y2='4' stroke={style.color} strokeWidth='2' strokeDasharray={style.dash} />
              </svg>
              {design}
            </button>
          )
        })}
      </div>
      <p className='m-0 text-[12px] text-ink-soft'>
        The dotted vertical line marks the current bidder count. The cost does not depend on the bids. A line breaks where the {profile}{' '}
        profile cannot hold the auction at {levels} levels.
      </p>
    </div>
  )
}
