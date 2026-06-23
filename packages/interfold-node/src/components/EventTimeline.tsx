// SPDX-License-Identifier: LGPL-3.0-only

import { useMemo, useState } from 'react'
import { absoluteTime, eventTime, json, short } from '../format'
import type { EventView } from '../types'

function SourceBadge({ source }: { source: EventView['source'] }) {
  const label = source === 'network' ? 'NET' : source.toUpperCase()
  return <span className={`source source--${source}`}>{label}</span>
}

function TraceLink({ value, label, onLocate }: { value: string; label?: string; onLocate: (id: string) => void }) {
  return (
    <button className='trace-link mono' type='button' title={value} onClick={() => onLocate(value)}>
      {label ?? short(value, 8, 4)}
    </button>
  )
}

function EventCard({ event, successors, onLocate }: { event: EventView; successors: EventView[]; onLocate: (id: string) => void }) {
  const [open, setOpen] = useState(false)
  const isRoot = event.event_id === event.causation_id
  return (
    <article id={`event-${event.event_id}`} className={`event-card event-card--${event.severity}`}>
      <button className='event-card__summary' type='button' onClick={() => setOpen((value) => !value)} aria-expanded={open}>
        <span className='event-card__rail' aria-hidden='true'>
          <span className='event-card__dot' />
        </span>
        <span className='event-card__time mono' title={absoluteTime(event.timestamp_us)}>
          {eventTime(event.timestamp_us)}
        </span>
        <span className='event-card__identity'>
          <strong>{event.event_type}</strong>
          <span className='event-card__meta'>
            <SourceBadge source={event.source} />
            <span>{short(event.producer, 12, 6)}</span>
            {event.block != null && <span className='mono'>block #{event.block.toLocaleString()}</span>}
          </span>
        </span>
        <span className='event-card__cause'>
          {isRoot ? 'origin' : `after ${short(event.causation_id, 6, 3)}`}
          <span className='chevron'>{open ? '−' : '+'}</span>
        </span>
      </button>
      {open && (
        <div className='event-card__detail'>
          <dl className='trace-grid'>
            <div>
              <dt>Event</dt>
              <dd>
                <TraceLink value={event.event_id} onLocate={onLocate} />
              </dd>
            </div>
            <div>
              <dt>Caused by</dt>
              <dd>
                <TraceLink value={event.causation_id} onLocate={onLocate} />
              </dd>
            </div>
            <div>
              <dt>Flow origin</dt>
              <dd>
                <TraceLink value={event.origin_id} onLocate={onLocate} />
              </dd>
            </div>
            <div>
              <dt>Followed by</dt>
              <dd className='trace-successors'>
                {successors.length ? (
                  successors.map((successor) => (
                    <TraceLink
                      key={successor.event_id}
                      value={successor.event_id}
                      label={`${successor.event_type} · ${short(successor.event_id, 5, 3)}`}
                      onLocate={onLocate}
                    />
                  ))
                ) : (
                  <span>Nothing observed yet</span>
                )}
              </dd>
            </div>
            <div>
              <dt>Local sequence</dt>
              <dd className='mono'>#{event.seq}</dd>
            </div>
            <div>
              <dt>HLC producer</dt>
              <dd className='mono'>{event.producer_fingerprint}</dd>
            </div>
            <div>
              <dt>Logical order</dt>
              <dd className='mono'>{event.logical_counter}</dd>
            </div>
          </dl>
          <div className='payload-head'>Structured payload</div>
          <pre className='payload'>{json(event.payload)}</pre>
        </div>
      )}
    </article>
  )
}

export default function EventTimeline({
  events,
  traceEvents = events,
  onNavigate,
  empty = 'No events observed for this stage yet.',
}: {
  events: EventView[]
  traceEvents?: EventView[]
  onNavigate?: (id: string) => void
  empty?: string
}) {
  const ids = useMemo(() => new Set(events.map((event) => event.event_id)), [events])
  const successors = useMemo(() => {
    const result = new Map<string, EventView[]>()
    for (const event of traceEvents) {
      if (event.causation_id === event.event_id) continue
      const following = result.get(event.causation_id) ?? []
      following.push(event)
      result.set(event.causation_id, following)
    }
    return result
  }, [traceEvents])
  const locate = (id: string) => {
    if (onNavigate) {
      onNavigate(id)
      return
    }
    const target = document.getElementById(`event-${id}`)
    if (target) {
      target.scrollIntoView({ behavior: 'smooth', block: 'center' })
      target.classList.add('event-card--located')
      window.setTimeout(() => target.classList.remove('event-card--located'), 1_400)
    } else if (!ids.has(id)) {
      document.getElementById('flow-origin-note')?.scrollIntoView({ behavior: 'smooth', block: 'center' })
    }
  }

  if (events.length === 0) return <div className='empty-inline'>{empty}</div>
  return (
    <div className='event-timeline'>
      {events.map((event) => (
        <EventCard
          event={event}
          successors={successors.get(event.event_id) ?? []}
          onLocate={locate}
          key={`${event.aggregate_id}-${event.seq}`}
        />
      ))}
    </div>
  )
}
