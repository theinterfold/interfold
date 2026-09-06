// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { Round, RoundStatus } from '@interfold/ckks-salary-sdk'
import { RoundTimeline, type RoundPhase } from '@interfold/ckks-editorial'
import { fmtTime } from '@/utils/constants'

const STEPS: { key: string; label: string; reached: (r: Round) => boolean; when: (r: Round) => number | null }[] = [
  { key: 'requested', label: 'E3 requested', reached: () => true, when: (r) => r.requested_at },
  {
    key: 'dkg',
    label: 'DKG + relin ceremony → joint key',
    reached: (r) => !!r.public_key_hex,
    when: (r) => r.key_published_at,
  },
  { key: 'open', label: 'Submissions open', reached: (r) => !!r.public_key_hex, when: (r) => r.input_window[0] },
  {
    key: 'closed',
    label: 'Window closed',
    reached: (r) => ['closed', 'evaluating', 'complete'].includes(r.status),
    when: (r) => r.input_window[1],
  },
  {
    key: 'evaluating',
    label: 'Evaluated (sum + Σx² homomorphically) → threshold decryption',
    reached: (r) => !!r.evaluation,
    when: (r) => r.evaluation?.evaluated_at ?? null,
  },
  { key: 'complete', label: 'Results published', reached: (r) => !!r.results, when: (r) => r.results?.decrypted_at ?? null },
]

export const statusLabel = (s: RoundStatus): string =>
  ({
    requested: 'Committee forming (DKG + ceremony)',
    open: 'Open for submissions',
    closed: 'Closed — awaiting evaluation',
    evaluating: 'Evaluated — committee decrypting',
    complete: 'Complete',
    failed: 'Failed',
  })[s]

/** Map the server's round status onto the editorial timeline phases. */
export const phaseOf = (r: Round): RoundPhase => {
  if (r.status === 'failed') return 'failed'
  if (r.results) return 'published'
  if (r.evaluation) return 'decrypting'
  if (r.status === 'evaluating' || r.status === 'closed') return 'evaluating'
  if (r.status === 'open' && r.public_key_hex) return 'open'
  return 'keygen'
}

export const StatusTimeline = ({ round }: { round: Round }) => (
  <div className="col" style={{ gap: 18 }}>
    <RoundTimeline phase={phaseOf(round)} committee={{ signed: round.public_key_hex ? round.committee.length || 5 : 0, total: round.committee.length || 5 }} />
    <ol className="proof-steps" data-testid="timeline">
      {STEPS.map((s, i) => {
        const done = s.reached(round)
        const when = s.when(round)
        return (
          <li key={s.key} className={`proof-step ${done ? 'done' : 'todo'}`} data-testid={`step-${s.key}`}>
            <span className="mono-sm num">{String(i + 1).padStart(2, '0')}</span>
            <span className="glyph" aria-hidden>
              {done ? '✓' : '○'}
            </span>
            <span className="lbl">{s.label}</span>
            <span className="mono-sm detail">{done && when ? fmtTime(when) : ''}</span>
          </li>
        )
      })}
    </ol>
  </div>
)
