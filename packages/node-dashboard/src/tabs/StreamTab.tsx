// SPDX-License-Identifier: LGPL-3.0-only
import { useEffect, useRef, useState } from 'react'
import type { ParsedEvent } from '../types'
import { extractType, hlcToTime, typeSev } from '../lib/events'

interface StreamTabProps {
  events: ParsedEvent[]
}

const SRC_LABELS: Record<string, string> = { Local: 'local', Net: 'net', Evm: 'evm' }

export default function StreamTab({ events }: StreamTabProps) {
  const [filter, setFilter] = useState('')
  const [autoScroll, setAutoScroll] = useState(true)
  const bottomRef = useRef<HTMLDivElement>(null)
  const lastCountRef = useRef(0)

  const lower = filter.toLowerCase()
  const filtered = filter
    ? events.filter((e) => {
        const t = extractType(e).toLowerCase()
        const src = (e.ctx?.source ?? '').toLowerCase()
        return t.includes(lower) || src.includes(lower)
      })
    : events

  const visible = filtered.slice(-500)

  useEffect(() => {
    if (autoScroll && events.length !== lastCountRef.current) {
      bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
    }
    lastCountRef.current = events.length
  }, [events.length, autoScroll])

  function handleScroll(e: React.UIEvent<HTMLDivElement>) {
    const el = e.currentTarget
    const nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 80
    setAutoScroll(nearBottom)
  }

  return (
    <div className='tab-pane stream-pane'>
      <div className='stream-toolbar'>
        <input
          className='filter-input'
          placeholder='Filter by type or source…'
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
        <span className='stream-count'>{filtered.length} events</span>
        <label className='autoscroll-label'>
          <input type='checkbox' checked={autoScroll} onChange={(e) => setAutoScroll(e.target.checked)} />
          Auto-scroll
        </label>
      </div>
      <div className='stream-feed' onScroll={handleScroll}>
        {visible.length === 0 && <div className='empty-state'>No events yet…</div>}
        {visible.map((evt) => {
          const type = extractType(evt)
          const sev = typeSev(type)
          const src = SRC_LABELS[evt.ctx?.source ?? ''] ?? evt.ctx?.source ?? ''
          const ts = hlcToTime(evt.ctx?.ts)
          return (
            <div key={evt.ctx?.seq ?? Math.random()} className={`stream-row sev-${sev || 'normal'}`}>
              <span className='s-ts'>{ts}</span>
              <span className={`s-src src-${src}`}>{src}</span>
              <span className={`s-type ${sev ? 'sev-badge-' + sev : ''}`}>{type}</span>
            </div>
          )
        })}
        <div ref={bottomRef} />
      </div>
    </div>
  )
}
