// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { Round, RoundStatus } from '@interfold/ckks-salary-sdk'
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

export const StatusTimeline = ({ round }: { round: Round }) => (
  <ol className="timeline" data-testid="timeline">
    {STEPS.map((s) => {
      const done = s.reached(round)
      const when = s.when(round)
      return (
        <li key={s.key} className={done ? 'done' : 'todo'} data-testid={`step-${s.key}`}>
          <span className="mark">{done ? '✓' : '○'}</span>
          <span>{s.label}</span>
          {done && when ? <span className="muted"> · {fmtTime(when)}</span> : null}
        </li>
      )
    })}
  </ol>
)
