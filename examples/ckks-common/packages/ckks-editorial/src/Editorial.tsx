// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
//
// Interfold editorial component library (the CRISP look), ported to TSX from the Claude Design
// handoff. Shared by every CKKS demo app. Pure presentational primitives;
// no app logic lives here.

import { useEffect, useMemo, useState, type ReactNode, type CSSProperties } from 'react'

/* ============================================================
   Numbered gutter — Nº 0X | LABEL  (vertical rule)
   ============================================================ */
export function Gutter({ num, label }: { num: string; label: string }) {
  return (
    <div className='gut'>
      <div className='num'>Nº {num}</div>
      <div className='vrule' />
      <div className='tag'>{label}</div>
    </div>
  )
}

/* ============================================================
   Ciphertext renderer — deterministic-looking hex blob whose
   blocks animate in. Purely decorative.
   ============================================================ */
const HEX = '0123456789abcdef'
function makeHex(seed: number, len: number): string {
  let s = seed
  let out = ''
  for (let i = 0; i < len; i++) {
    s = (s * 16807 + 7) % 2147483647
    out += HEX[s & 15]
  }
  return out
}

export function Cipher({
  seed = 42,
  length = 96,
  blockSize = 4,
  highlight = false,
  tight = false,
  className = '',
}: {
  seed?: number
  length?: number
  blockSize?: number
  highlight?: boolean
  tight?: boolean
  className?: string
}) {
  const blocks = useMemo(() => {
    const step = Math.max(1, Math.floor(blockSize))
    const raw = makeHex(seed + length, length)
    const arr: string[] = []
    for (let i = 0; i < length; i += step) arr.push(raw.slice(i, i + step))
    return arr
  }, [seed, length, blockSize])
  return (
    <span className={`cipher ${tight ? 'tight' : ''} ${className}`}>
      {blocks.map((b, i) => (
        <span
          key={i}
          className='blk'
          style={{
            animationDelay: `${i * 18}ms`,
            color: highlight && i % 7 === 0 ? 'var(--accent)' : undefined,
            fontWeight: highlight && i % 7 === 0 ? 600 : undefined,
          }}
        >
          {b}
          {i < blocks.length - 1 ? ' ' : ''}
        </span>
      ))}
    </span>
  )
}

/* ============================================================
   Threshold custodian seals
   ============================================================ */
type SealState = 'signed' | 'pending' | 'active'

export function ThresholdSeal({ id, state }: { id: string; state: SealState }) {
  const cls = state === 'signed' ? 'active' : state === 'pending' ? 'pending' : ''
  return (
    <div className={`seal ${cls}`}>
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }}>
        <div style={{ fontSize: 9, opacity: 0.75 }}>C—{id}</div>
        <div style={{ fontSize: 14, fontWeight: 600 }}>{state === 'signed' ? '✓' : state === 'pending' ? '·' : '○'}</div>
      </div>
    </div>
  )
}

export function ThresholdRow({ signed, total }: { signed: number; total: number }) {
  return (
    <div className='threshold-row'>
      {Array.from({ length: total }).map((_, i) => (
        <ThresholdSeal key={i} id={String(i + 1).padStart(2, '0')} state={i < signed ? 'signed' : i === signed ? 'active' : 'pending'} />
      ))}
    </div>
  )
}

/* ============================================================
   Tally bar — horizontal segments with mono labels
   ============================================================ */
export interface TallySegment {
  label?: string
  count: number
  color?: 'a' | 'b'
}

export function TallyBar({ segments, total }: { segments: TallySegment[]; total: number }) {
  return (
    <div className='tally-bar'>
      {segments.map((s, i) => {
        const pct = total > 0 ? (s.count / total) * 100 : 0
        return (
          <div key={i} className={`seg ${s.color || 'a'}`} style={{ width: `${pct}%` }}>
            {pct >= 8 ? `${Math.round(pct)}%` : ''}
          </div>
        )
      })}
    </div>
  )
}

/* ============================================================
   Section header — Nº NN | TITLE | meta on right
   ============================================================ */
export function SectionHeader({
  num,
  kicker,
  title,
  meta,
  children,
}: {
  num: string
  kicker: string
  title: ReactNode
  meta?: ReactNode
  children?: ReactNode
}) {
  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: '80px 1fr auto',
        gap: 24,
        alignItems: 'end',
        paddingBottom: 18,
        borderBottom: '1px solid var(--rule-strong)',
      }}
    >
      <div>
        <div className='mono' style={{ color: 'var(--ink-soft)' }}>
          Nº {num}
        </div>
        <div className='mono' style={{ marginTop: 4 }}>
          {kicker}
        </div>
      </div>
      <div className='h2'>{title}</div>
      <div className='cap txt-right'>{meta}</div>
      {children}
    </div>
  )
}

/* ============================================================
   Hand-drawn markers (SVG strike / underline)
   ============================================================ */
export function MarkerStrike({ children, color = 'var(--accent)' }: { children: ReactNode; color?: string }) {
  return (
    <span style={{ position: 'relative', display: 'inline-block' }}>
      {children}
      <svg
        style={{ position: 'absolute', left: '-4%', right: '-4%', top: '42%', width: '108%', height: '0.5em', pointerEvents: 'none' }}
        viewBox='0 0 200 20'
        preserveAspectRatio='none'
      >
        <path
          d='M2 12 C 40 6, 80 16, 120 9 S 198 8, 198 11'
          stroke={color}
          strokeWidth='3.5'
          fill='none'
          strokeLinecap='round'
          opacity='0.9'
        />
      </svg>
    </span>
  )
}

export function MarkerUnderline({ children, color = 'var(--accent)' }: { children: ReactNode; color?: string }) {
  return (
    <span style={{ position: 'relative', display: 'inline-block' }}>
      {children}
      <svg
        style={{
          position: 'absolute',
          left: '-3%',
          right: '-3%',
          bottom: '-0.18em',
          width: '106%',
          height: '0.34em',
          pointerEvents: 'none',
        }}
        viewBox='0 0 200 14'
        preserveAspectRatio='none'
      >
        <path d='M2 8 C 50 2, 150 12, 198 5' stroke={color} strokeWidth='2.5' fill='none' strokeLinecap='round' opacity='0.85' />
      </svg>
    </span>
  )
}

/* ============================================================
   Countdown — mono digits to a target epoch (ms)
   ============================================================ */
export function Countdown({ targetMs }: { targetMs: number }) {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(t)
  }, [])
  const diff = Math.max(0, targetMs - now)
  const d = Math.floor(diff / 86400000)
  const h = Math.floor((diff / 3600000) % 24)
  const m = Math.floor((diff / 60000) % 60)
  const s = Math.floor((diff / 1000) % 60)
  const seg = (n: number, lbl: string) => (
    <span style={{ display: 'inline-flex', alignItems: 'baseline', gap: 4 }}>
      <span style={{ fontFamily: 'var(--f-mono)', fontSize: 28, fontWeight: 500, letterSpacing: '-0.02em' }}>
        {String(n).padStart(2, '0')}
      </span>
      <span className='mono-sm' style={{ color: 'var(--ink-soft)' }}>
        {lbl}
      </span>
    </span>
  )
  return (
    <div style={{ display: 'inline-flex', gap: 18, alignItems: 'baseline' }}>
      {seg(d, 'd')} {seg(h, 'h')} {seg(m, 'm')} {seg(s, 's')}
    </div>
  )
}

/* ============================================================
   EditorialShell — opt-in wrapper that scopes the design tokens
   (palette / mode / density) for a page or subtree.
   ============================================================ */
export function EditorialShell({
  children,
  palette = 'interfold',
  mode = 'light',
  density = 'comfortable',
  className = '',
  style,
}: {
  children: ReactNode
  palette?: string
  mode?: 'light' | 'dark'
  density?: 'comfortable' | 'compact'
  className?: string
  style?: CSSProperties
}) {
  return (
    <div className={`crisp-editorial ${className}`} data-palette={palette} data-mode={mode} data-density={density} style={style}>
      {children}
    </div>
  )
}
