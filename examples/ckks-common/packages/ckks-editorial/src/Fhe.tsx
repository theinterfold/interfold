// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
//
// FHE-specific editorial components shared by the six CKKS demo apps.
// Everything here is presentational: the apps pass in the state they get
// from their own hooks/servers. Nothing imports app code.

import type { ReactNode } from 'react'
import { Cipher, Countdown, ThresholdRow } from './Editorial'

/* ============================================================
   Proof-step ladder — the client-side pipeline every CKKS app runs:
   encrypt → prove N legs → wallet tx → on-chain verify.
   ============================================================ */
export type StepState = 'todo' | 'running' | 'done' | 'failed'

export interface ProofStep {
  label: string
  state: StepState
  /** Mono detail on the right (e.g. "1.6 s", "14 656 B", a tx hash). */
  detail?: ReactNode
}

export function ProofSteps({ steps, testId }: { steps: ProofStep[]; testId?: string }) {
  return (
    <ol className='proof-steps' data-testid={testId}>
      {steps.map((s, i) => (
        <li key={i} className={`proof-step ${s.state}`}>
          <span className='mono-sm num'>{String(i + 1).padStart(2, '0')}</span>
          <span className='glyph' aria-hidden>
            {s.state === 'done' ? '✓' : s.state === 'failed' ? '✕' : s.state === 'running' ? '·' : '○'}
          </span>
          <span className='lbl'>{s.label}</span>
          <span className='mono-sm detail'>{s.detail}</span>
        </li>
      ))}
    </ol>
  )
}

/* ============================================================
   Round status — the E3 lifecycle as the committee sees it.
   ============================================================ */
export type RoundPhase = 'requested' | 'keygen' | 'ceremony' | 'open' | 'evaluating' | 'decrypting' | 'published' | 'failed'

const PHASES: { key: RoundPhase; label: string }[] = [
  { key: 'requested', label: 'Requested' },
  { key: 'keygen', label: 'DKG' },
  { key: 'ceremony', label: 'Relin ceremony' },
  { key: 'open', label: 'Accepting inputs' },
  { key: 'evaluating', label: 'Computing' },
  { key: 'decrypting', label: 'Threshold decrypt' },
  { key: 'published', label: 'Published' },
]

export function RoundTimeline({
  phase,
  committee,
  testId,
}: {
  phase: RoundPhase
  /** { signed, total } — how many committee members have published for the current step. */
  committee?: { signed: number; total: number }
  testId?: string
}) {
  const idx = PHASES.findIndex((p) => p.key === phase)
  return (
    <div className='round-timeline' data-testid={testId} data-phase={phase}>
      <ol>
        {PHASES.map((p, i) => (
          <li key={p.key} className={i < idx ? 'done' : i === idx ? 'current' : ''}>
            <span className='dot' />
            <span className='mono-sm'>{p.label}</span>
          </li>
        ))}
      </ol>
      {committee && <ThresholdRow signed={committee.signed} total={committee.total} />}
      {phase === 'failed' && <span className='tag closed'>failed</span>}
    </div>
  )
}

/* ============================================================
   Encrypted-input card — what the user just produced, shown as
   a ciphertext blob with the proof legs beneath it.
   ============================================================ */
export function EncryptedInputCard({
  title,
  seed,
  legs,
  bytes,
  children,
}: {
  title: ReactNode
  seed: number
  /** Proof legs attached to this ciphertext (e.g. ["Greco ct0", "Greco ct1"]). */
  legs: string[]
  bytes?: number
  children?: ReactNode
}) {
  return (
    <div className='card col' style={{ gap: 14 }}>
      <div className='between'>
        <span className='mono muted'>{title}</span>
        {bytes !== undefined && <span className='mono-sm muted'>{bytes.toLocaleString()} B</span>}
      </div>
      <Cipher seed={seed} length={112} blockSize={4} highlight />
      <div className='row' style={{ gap: 8, flexWrap: 'wrap' }}>
        {legs.map((l) => (
          <span key={l} className='tag'>
            {l}
          </span>
        ))}
      </div>
      {children}
    </div>
  )
}

/* ============================================================
   Opened-result card — the ONE thing the committee decrypted.
   Big serif number, mono caption saying what it is and is not.
   ============================================================ */
export function ResultCard({
  label,
  value,
  unit,
  caption,
  reveals,
  hides,
  testId,
}: {
  label: ReactNode
  value: ReactNode
  unit?: ReactNode
  caption?: ReactNode
  /** What this opening reveals. */
  reveals?: ReactNode
  /** What it deliberately does not. */
  hides?: ReactNode
  testId?: string
}) {
  return (
    <div className='card result-card col' style={{ gap: 16 }} data-testid={testId}>
      <div className='mono muted'>{label}</div>
      <div className='result-value'>
        <span className='display' style={{ fontSize: 'clamp(40px, 6vw, 72px)' }}>
          {value}
        </span>
        {unit && (
          <span className='mono muted' style={{ marginLeft: 12 }}>
            {unit}
          </span>
        )}
      </div>
      {caption && <div className='cap'>{caption}</div>}
      {(reveals || hides) && (
        <div className='split' style={{ gap: 24 }}>
          {reveals && (
            <div className='col' style={{ gap: 6 }}>
              <span className='mono-sm accent'>Revealed</span>
              <span className='muted'>{reveals}</span>
            </div>
          )}
          {hides && (
            <div className='col' style={{ gap: 6 }}>
              <span className='mono-sm muted'>Never opened</span>
              <span className='muted'>{hides}</span>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

/* ============================================================
   Round card — list item for the Rounds page.
   ============================================================ */
export function RoundCard({
  num,
  title,
  status,
  endsAtMs,
  meta,
  onClick,
  testId,
}: {
  num: string
  title: ReactNode
  status: 'live' | 'closed' | 'pending'
  endsAtMs?: number
  meta?: ReactNode
  onClick?: () => void
  testId?: string
}) {
  return (
    <button type='button' className='card round-card' onClick={onClick} data-testid={testId}>
      <div className='between' style={{ width: '100%' }}>
        <span className='mono muted'>Nº {num}</span>
        <span className={`tag dot ${status}`}>{status}</span>
      </div>
      <div className='h3' style={{ textAlign: 'left' }}>
        {title}
      </div>
      <div className='between' style={{ width: '100%' }}>
        <span className='cap'>{meta}</span>
        {status === 'live' && endsAtMs !== undefined && <Countdown targetMs={endsAtMs} />}
      </div>
    </button>
  )
}

/* ============================================================
   Honest-scope notice — every demo carries the same caveats.
   ============================================================ */
export function HonestScope({ items }: { items: ReactNode[] }) {
  return (
    <aside className='card honest-scope col' style={{ gap: 10 }}>
      <div className='mono muted'>Demo scope — read before trusting a number</div>
      <ul className='col' style={{ gap: 6, margin: 0, paddingLeft: 18 }}>
        {items.map((it, i) => (
          <li key={i} className='muted'>
            {it}
          </li>
        ))}
      </ul>
    </aside>
  )
}

/* ============================================================
   Wallet pill — the anvil-key / injected-wallet chooser every
   CKKS app has, in editorial dress.
   ============================================================ */
export function WalletPill({
  label,
  address,
  onClick,
  testId,
}: {
  label: ReactNode
  address?: string
  onClick?: () => void
  testId?: string
}) {
  const short = address ? `${address.slice(0, 6)}…${address.slice(-4)}` : ''
  return (
    <button type='button' className='wallet' onClick={onClick} data-testid={testId}>
      <span className='blockie' style={{ background: address ? `#${address.slice(2, 8)}` : 'var(--rule-strong)' }} />
      <span>{label}</span>
      {short && <span className='mono-sm muted'>{short}</span>}
    </button>
  )
}
