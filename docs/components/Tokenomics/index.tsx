// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useRef, useState } from 'react'
import classes from './Tokenomics.module.css'

// ---------------------------------------------------------------------------
// Source data — Token Distribution Scheme (tab 1 of the allocation sheet)
// ---------------------------------------------------------------------------

export const TOTAL_SUPPLY = 1_200_000_000

type Slice = {
  key: string
  pct: number
  tokens: number
  color: string
}

// Ordered largest → smallest. Colours are a cohesive cool/azure palette
// anchored on the docs' primary hue (203) so the charts match the theme.
const ALLOCATION: Slice[] = [
  { key: 'Community Grants & Treasury', pct: 47, tokens: 564_000_000, color: '#075E9D' },
  { key: 'Gnosis Guild', pct: 20, tokens: 240_000_000, color: '#009DFF' },
  { key: 'Investors', pct: 15, tokens: 180_000_000, color: '#38BDF8' },
  { key: 'Uniswap CCA', pct: 10, tokens: 120_000_000, color: '#0D9488' },
  { key: 'Airdrop', pct: 4, tokens: 48_000_000, color: '#6366F1' },
  { key: 'Liquidity Reserves', pct: 3, tokens: 36_000_000, color: '#818CF8' },
  { key: 'Advisors', pct: 1, tokens: 12_000_000, color: '#94A3B8' },
]

const COLOR_BY_KEY: Record<string, string> = Object.fromEntries(
  ALLOCATION.map(s => [s.key, s.color]),
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const fmtInt = (n: number) => n.toLocaleString('en-US')

const fmtPct = (n: number) => `${Math.round(n)}%`

const fmtCompact = (n: number) => {
  if (n >= 1e9) return `${(n / 1e9).toFixed(n % 1e9 === 0 ? 0 : 2)}B`
  if (n >= 1e6) return `${Math.round(n / 1e6)}M`
  return fmtInt(n)
}

function polar(cx: number, cy: number, r: number, angleDeg: number): [number, number] {
  const a = ((angleDeg - 90) * Math.PI) / 180
  return [cx + r * Math.cos(a), cy + r * Math.sin(a)]
}

function donutSlice(
  cx: number,
  cy: number,
  rOuter: number,
  rInner: number,
  start: number,
  end: number,
): string {
  const [x1, y1] = polar(cx, cy, rOuter, end)
  const [x2, y2] = polar(cx, cy, rOuter, start)
  const [x3, y3] = polar(cx, cy, rInner, start)
  const [x4, y4] = polar(cx, cy, rInner, end)
  const large = end - start > 180 ? 1 : 0
  return [
    `M ${x1} ${y1}`,
    `A ${rOuter} ${rOuter} 0 ${large} 0 ${x2} ${y2}`,
    `L ${x3} ${y3}`,
    `A ${rInner} ${rInner} 0 ${large} 1 ${x4} ${y4}`,
    'Z',
  ].join(' ')
}

// ---------------------------------------------------------------------------
// Key parameters
// ---------------------------------------------------------------------------

export function KeyParameters() {
  const cards = [
    { label: 'Total Supply', value: '1.2B' },
    { label: 'Circulating Supply at TGE', value: '17%' },
  ]
  return (
    <div className={classes.stats}>
      {cards.map(c => (
        <div key={c.label} className={classes.statCard}>
          <p className={classes.statLabel}>{c.label}</p>
          <div className={classes.statValue}>{c.value}</div>
        </div>
      ))}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Allocation donut + legend
// ---------------------------------------------------------------------------

export function AllocationPie() {
  const size = 260
  const cx = size / 2
  const cy = size / 2
  const rOuter = 122
  const rInner = 74
  const POP = 7

  const [hover, setHover] = useState<string | null>(null)
  const [pos, setPos] = useState({ x: 0, y: 0 })
  const wrapRef = useRef<HTMLDivElement>(null)

  let cursor = 0
  const total = ALLOCATION.reduce((s, d) => s + d.pct, 0)
  const arcs = ALLOCATION.map(d => {
    const start = (cursor / total) * 360
    cursor += d.pct
    const end = (cursor / total) * 360
    const mid = (((start + end) / 2 - 90) * Math.PI) / 180
    return { ...d, start, end, dx: Math.cos(mid) * POP, dy: Math.sin(mid) * POP }
  })

  const hovered = ALLOCATION.find(d => d.key === hover)

  const onMove = (e: React.MouseEvent) => {
    const r = wrapRef.current?.getBoundingClientRect()
    if (r) setPos({ x: e.clientX - r.left, y: e.clientY - r.top })
  }

  return (
    <div className={classes.allocation} ref={wrapRef} onMouseMove={onMove}>
      <div className={classes.pieWrap}>
        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img"
          aria-label="Token distribution by category">
          {arcs.map(a => {
            const isHover = hover === a.key
            return (
              <path
                key={a.key}
                d={donutSlice(cx, cy, rOuter, rInner, a.start, a.end)}
                fill={a.color}
                stroke="#ffffff"
                strokeWidth={2.5}
                style={{
                  transition: 'transform 0.18s ease, opacity 0.18s ease',
                  transform: isHover ? `translate(${a.dx}px, ${a.dy}px)` : 'none',
                  opacity: hover && !isHover ? 0.78 : 1,
                  cursor: 'pointer',
                }}
                onMouseEnter={() => setHover(a.key)}
                onMouseLeave={() => setHover(null)}
              />
            )
          })}
          <text x={cx} y={cy - 6} textAnchor="middle" fontSize="30" fontWeight="700" fill="#0f2233">
            1.2B
          </text>
          <text x={cx} y={cy + 16} textAnchor="middle" fontSize="11" letterSpacing="0.08em" fill="#6b7280">
            TOTAL SUPPLY
          </text>
        </svg>
      </div>

      <table className={classes.legend}>
        <thead>
          <tr>
            <th>Category</th>
            <th className={classes.center}>Supply</th>
            <th className={classes.center}>Tokens</th>
          </tr>
        </thead>
        <tbody>
          {ALLOCATION.map(d => (
            <tr
              key={d.key}
              onMouseEnter={() => setHover(d.key)}
              onMouseLeave={() => setHover(null)}
              style={{ background: hover === d.key ? 'rgba(15,23,42,0.05)' : undefined }}
            >
              <td className={classes.catCell}>
                <span className={classes.swatch} style={{ background: d.color }} />
                {d.key}
              </td>
              <td className={classes.center}>{fmtPct(d.pct)}</td>
              <td className={classes.center}>{fmtInt(d.tokens)}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {hovered && (
        <div className={classes.tooltip} style={{ left: pos.x, top: pos.y }}>
          {hovered.key}
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Vesting schedule — cumulative stacked-area chart (circulating supply)
// ---------------------------------------------------------------------------

type Vest = {
  key: string
  total: number // tokens
  vestMonths: number // linear duration; 1 = fully unlocked at TGE
  term: string
}

// Bottom → top stacking order (flat/immediate at the base, long linear vests on
// top).
const VESTING: Vest[] = [
  { key: 'Liquidity Reserves', total: 36_000_000, vestMonths: 1, term: '100% at TGE' },
  { key: 'Uniswap CCA', total: 120_000_000, vestMonths: 1, term: '100% at TGE' },
  { key: 'Airdrop', total: 48_000_000, vestMonths: 24, term: '24-month linear unlock' },
  { key: 'Advisors', total: 12_000_000, vestMonths: 24, term: '24-month linear unlock' },
  { key: 'Investors', total: 180_000_000, vestMonths: 24, term: '24-month linear unlock' },
  { key: 'Gnosis Guild', total: 240_000_000, vestMonths: 48, term: '48-month linear unlock' },
  { key: 'Community Grants & Treasury', total: 564_000_000, vestMonths: 48, term: '48-month linear unlock' },
]

// Vesting terms table — same order as the allocation table (largest → smallest
// share). Cliffs are all zero in the source schedule.
const VESTING_TERMS = [
  { key: 'Community Grants & Treasury', cliff: 'None', schedule: '48 months' },
  { key: 'Gnosis Guild', cliff: 'None', schedule: '48 months' },
  { key: 'Investors', cliff: 'None', schedule: '24 months' },
  { key: 'Uniswap CCA', cliff: 'None', schedule: '100% at TGE' },
  { key: 'Airdrop', cliff: 'None', schedule: '24 months' },
  { key: 'Liquidity Reserves', cliff: 'None', schedule: '100% at TGE' },
  { key: 'Advisors', cliff: 'None', schedule: '24 months' },
]

const MONTHS_AXIS = 48
const X_TICKS = [0, 12, 24, 36, 48]
const X_LABELS = ['TGE', '12 mo', '24 mo', '36 mo', '48 mo']
const Y_MAX = 1_200_000_000
const Y_TICKS = [0, 300_000_000, 600_000_000, 900_000_000, 1_200_000_000]
const Y_LABELS = ['0', '300M', '600M', '900M', '1.2B']

// Cumulative tokens unlocked for a category at month t (first tranche at TGE).
function cumulative(v: Vest, t: number): number {
  return (v.total * Math.min(t + 1, v.vestMonths)) / v.vestMonths
}

export function VestingSchedule() {
  const W = 860
  const H = 380
  const padL = 56
  const padR = 24
  const padT = 24
  const padB = 48
  const plotW = W - padL - padR
  const plotH = H - padT - padB

  const x = (t: number) => padL + (t / MONTHS_AXIS) * plotW
  const y = (v: number) => padT + plotH - (v / Y_MAX) * plotH

  // Build cumulative stacked boundaries for each band.
  const months = Array.from({ length: MONTHS_AXIS + 1 }, (_, t) => t)
  let running = months.map(() => 0)
  const bands = VESTING.map(v => {
    const lower = running.slice()
    const upper = months.map((t, i) => lower[i] + cumulative(v, t))
    running = upper
    // polygon: upper boundary L→R, then lower boundary R→L
    const top = months.map((t, i) => `${x(t).toFixed(1)},${y(upper[i]).toFixed(1)}`)
    const bot = months.map((t, i) => `${x(t).toFixed(1)},${y(lower[i]).toFixed(1)}`).reverse()
    return { key: v.key, color: COLOR_BY_KEY[v.key], d: `M ${top.join(' L ')} L ${bot.join(' L ')} Z` }
  })

  const [hover, setHover] = useState<string | null>(null)
  const [tip, setTip] = useState(false)
  const [pos, setPos] = useState({ x: 0, y: 0 })
  const wrapRef = useRef<HTMLDivElement>(null)

  const onMove = (e: React.MouseEvent) => {
    const r = wrapRef.current?.getBoundingClientRect()
    if (r) setPos({ x: e.clientX - r.left, y: e.clientY - r.top })
  }

  return (
    <div className={classes.vesting} ref={wrapRef} onMouseMove={onMove}>
      <div className={classes.svgScroll}>
        <svg width="100%" viewBox={`0 0 ${W} ${H}`} role="img"
          aria-label="Cumulative circulating supply by category over time" style={{ minWidth: 600 }}>
          {/* horizontal gridlines + y labels */}
          {Y_TICKS.map((t, i) => (
            <g key={t}>
              <line x1={padL} y1={y(t)} x2={W - padR} y2={y(t)} stroke="#ece3d4" strokeWidth={1} />
              <text x={padL - 10} y={y(t) + 4} textAnchor="end" fontSize="11" fill="#9aa3b0">
                {Y_LABELS[i]}
              </text>
            </g>
          ))}

          {/* stacked area bands */}
          {bands.map(b => {
            const isHover = hover === b.key
            return (
              <path
                key={b.key}
                d={b.d}
                fill={b.color}
                stroke="#ffffff"
                strokeWidth={isHover ? 1.5 : 0.75}
                style={{
                  transition: 'opacity 0.18s ease, filter 0.18s ease',
                  opacity: hover && !isHover ? 0.72 : 1,
                  filter: isHover ? 'brightness(1.08)' : 'none',
                  cursor: 'pointer',
                }}
                onMouseEnter={() => {
                  setHover(b.key)
                  setTip(true)
                }}
                onMouseLeave={() => {
                  setHover(null)
                  setTip(false)
                }}
              />
            )
          })}

          {/* x ticks + labels */}
          {X_TICKS.map((m, i) => (
            <g key={m}>
              <line x1={x(m)} y1={padT} x2={x(m)} y2={padT + plotH} stroke="#ece3d4" strokeWidth={m === 0 ? 0 : 1} />
              <text x={x(m)} y={padT + plotH + 20} textAnchor="middle" fontSize="11" fill="#6b7280">
                {X_LABELS[i]}
              </text>
            </g>
          ))}

        </svg>
      </div>

      <div className={classes.vtableWrap}>
        <table className={classes.legend}>
          <thead>
            <tr>
              <th>Category</th>
              <th className={classes.num}>Linear Unlock</th>
            </tr>
          </thead>
          <tbody>
            {VESTING_TERMS.map(v => (
              <tr
                key={v.key}
                onMouseEnter={() => {
                  setHover(v.key)
                  setTip(false)
                }}
                onMouseLeave={() => setHover(null)}
                style={{ background: hover === v.key ? 'rgba(15,23,42,0.05)' : undefined }}
              >
                <td className={classes.catCell}>
                  <span className={classes.swatch} style={{ background: COLOR_BY_KEY[v.key] }} />
                  {v.key}
                </td>
                <td className={classes.num}>{v.schedule}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {tip && hover && (
        <div className={classes.tooltip} style={{ left: pos.x, top: pos.y }}>
          {hover}
        </div>
      )}
    </div>
  )
}
