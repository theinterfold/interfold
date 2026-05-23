// SPDX-License-Identifier: LGPL-3.0-only
import type { E3Entry } from '../types'
import { STEPS } from '../lib/events'

interface PipelineTabProps {
  e3s: Record<string, E3Entry>
}

export default function PipelineTab({ e3s }: PipelineTabProps) {
  const entries = Object.entries(e3s)
  entries.sort(([, a], [, b]) => (a.latestTs < b.latestTs ? 1 : -1))

  if (entries.length === 0) {
    return <div className='tab-pane empty-state'>No E3 requests observed yet.</div>
  }

  return (
    <div className='tab-pane pipeline-pane'>
      {entries.map(([id, e]) => (
        <E3Card key={id} id={id} entry={e} />
      ))}
    </div>
  )
}

function E3Card({ id, entry: e }: { id: string; entry: E3Entry }) {
  const pct = Math.round(((e.stepIdx + 1) / STEPS.length) * 100)
  return (
    <div className={`e3-card${e.error ? ' e3-error' : ''}`}>
      <div className='e3-card-head'>
        <span className='e3-id'>E3 {id}</span>
        <span className='e3-ts'>{e.latestTs}</span>
        {e.error && <span className='e3-err-badge'>failed</span>}
      </div>
      <div className='progress-bar'>
        <div className='progress-fill' style={{ width: `${pct}%` }} />
      </div>
      <div className='step-labels'>
        {STEPS.map((s, i) => {
          const done = i <= e.stepIdx
          const active = i === e.stepIdx
          return (
            <div key={s.id} className={`step-label${done ? ' done' : ''}${active ? ' active' : ''}`}>
              <div className='step-dot' />
              <span>{s.label}</span>
            </div>
          )
        })}
      </div>
      {e.evLog.length > 0 && (
        <div className='e3-evlog'>
          {e.evLog.slice(-6).map((ev, i) => (
            <div key={i} className='e3-evrow'>
              <span className='s-ts'>{ev.ts}</span>
              <span className={`s-src src-${ev.src.toLowerCase()}`}>{ev.src}</span>
              <span className='s-type'>{ev.type}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
