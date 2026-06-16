// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
// Poll history archive — past completed polls. Rows expand to show detail.

import { useState } from 'react'

type Entry = {
  id: string
  question: string
  closed: string
  duration: string
  ballotCount: number
  result: string
}

const HIST_FILTERS = [
  { id: 'all', label: 'All', test: () => true },
  { id: 'appr', label: 'Approved', test: (e: Entry) => /Approved|Adopted|Completed/i.test(e.result) },
  { id: 'failed', label: 'Failed', test: (e: Entry) => /Failed/i.test(e.result) },
  { id: 'expired', label: 'Expired', test: (e: Entry) => /Expired/i.test(e.result) },
]

function HistoryDetail({ entry, onNavigate }: { entry: Entry; onNavigate?: (view: string) => void }) {
  return (
    <div className='hist-detail'>
      <dl className='hist-detail__dl'>
        <dt>Result</dt>
        <dd>{entry.result}</dd>
        <dt>Ballots</dt>
        <dd className='mono'>{entry.ballotCount.toLocaleString()}</dd>
        <dt>Open for</dt>
        <dd className='mono'>{entry.duration}</dd>
        <dt>Closed</dt>
        <dd className='mono'>{entry.closed}</dd>
        <dt>Privacy</dt>
        <dd>No individual ballot was ever decrypted.</dd>
      </dl>

      <div className='hist-detail__foot'>
        <a
          className='link-inline'
          href='#'
          onClick={(e) => {
            e.preventDefault()
            onNavigate?.('inspector')
          }}
        >
          Open full inspector view
          <span aria-hidden='true'>→</span>
        </a>
      </div>
    </div>
  )
}

function HistoryRow({
  entry,
  expanded,
  onToggle,
  onNavigate,
}: {
  entry: Entry
  expanded: boolean
  onToggle: () => void
  onNavigate?: (view: string) => void
}) {
  const [winner, pct] = entry.result.split(' · ')
  const lower = winner.toLowerCase()
  const bad = /declined|failed|expired/.test(lower)
  const good = /approved|adopted|completed/.test(lower)
  const tone = bad ? 'hist-row__verdict--bad' : good ? 'hist-row__verdict--good' : ''
  return (
    <li className={`hist-row ${expanded ? 'hist-row--open' : ''}`}>
      <button type='button' className='hist-row__btn' onClick={onToggle} aria-expanded={expanded}>
        <div className='hist-row__main'>
          <div className='hist-row__meta'>
            <span className='hist-row__id mono'>{entry.id}</span>
            <span className='hist-row__sep'>·</span>
            <span className='hist-row__date'>{entry.closed}</span>
            <span className='hist-row__sep'>·</span>
            <span className='hist-row__dur'>{entry.duration}</span>
          </div>
          <div className='hist-row__q'>{entry.question}</div>
        </div>
        <div className='hist-row__result'>
          <div className={`hist-row__verdict ${tone}`}>
            <span className='hist-row__verdict-text'>{winner}</span>
            <span className='hist-row__verdict-pct mono'>{pct}</span>
          </div>
          <div className='hist-row__ballots mono'>{entry.ballotCount.toLocaleString()} ballots</div>
        </div>
        <span className={`hist-row__chev ${expanded ? 'hist-row__chev--open' : ''}`} aria-hidden='true'>
          <svg viewBox='0 0 12 12' width='12' height='12'>
            <path d='M4 2 L8 6 L4 10' fill='none' stroke='currentColor' strokeWidth='1.4' strokeLinecap='round' strokeLinejoin='round' />
          </svg>
        </span>
      </button>
      {expanded && <HistoryDetail entry={entry} onNavigate={onNavigate} />}
    </li>
  )
}

export default function History({ entries, onNavigate }: { entries: Entry[]; onNavigate?: (view: string) => void }) {
  const [filterId, setFilterId] = useState('all')
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const filter = HIST_FILTERS.find((f) => f.id === filterId) || HIST_FILTERS[0]
  const filtered = entries.filter(filter.test as any)

  return (
    <section className='history' aria-label='Poll history'>
      <header className='history__head'>
        <div>
          <div className='section__eyebrow'>Archive</div>
          <h2 className='section__title'>Past polls</h2>
        </div>
        <div className='history__filters'>
          {HIST_FILTERS.map((f) => (
            <button key={f.id} type='button' className={`chip ${filterId === f.id ? 'chip--on' : ''}`} onClick={() => setFilterId(f.id)}>
              {f.label}
            </button>
          ))}
        </div>
      </header>
      <ul className='hist-list'>
        {filtered.map((e) => (
          <HistoryRow
            key={e.id}
            entry={e}
            expanded={expandedId === e.id}
            onToggle={() => setExpandedId((cur) => (cur === e.id ? null : e.id))}
            onNavigate={onNavigate}
          />
        ))}
        {filtered.length === 0 && <li className='hist-empty'>No polls match this filter.</li>}
      </ul>
    </section>
  )
}
