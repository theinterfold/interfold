// SPDX-License-Identifier: LGPL-3.0-only

import { useMemo, useState } from 'react'
import { useEvents } from '../api'
import EventTimeline from '../components/EventTimeline'
import type { EventSeverity, EventSource } from '../types'

export default function EventsView() {
  const query = useEvents()
  const events = useMemo(() => query.data?.events ?? [], [query.data?.events])
  const [search, setSearch] = useState('')
  const [source, setSource] = useState<EventSource | 'all'>('all')
  const [severity, setSeverity] = useState<EventSeverity | 'all'>('all')
  const sourceCounts = useMemo(
    () => ({
      local: events.filter((event) => event.source === 'local').length,
      network: events.filter((event) => event.source === 'network').length,
      evm: events.filter((event) => event.source === 'evm').length,
    }),
    [events],
  )
  const sourceTotal = Math.max(1, sourceCounts.local + sourceCounts.network + sourceCounts.evm)
  const filtered = useMemo(() => {
    const needle = search.toLowerCase().trim()
    return events.filter((event) => {
      if (source !== 'all' && event.source !== source) return false
      if (severity !== 'all' && event.severity !== severity) return false
      return (
        !needle ||
        `${event.event_type} ${event.e3_id ?? ''} ${event.producer} ${JSON.stringify(event.payload)}`.toLowerCase().includes(needle)
      )
    })
  }, [events, search, severity, source])
  return (
    <div className='view-stack'>
      <header className='view-title'>
        <div>
          <span className='section-kicker'>EventStore</span>
          <h1>Raw protocol activity</h1>
          <p>The latest durable facts observed by this node across local, network, and EVM sources.</p>
        </div>
      </header>
      <section className='source-viz' aria-label='Protocol event sources'>
        {(['local', 'network', 'evm'] as const).map((name) => (
          <button
            type='button'
            onClick={() => setSource(name)}
            key={name}
            className={source === name ? 'source-viz__item source-viz__item--selected' : 'source-viz__item'}
          >
            <span>{name}</span>
            <strong className='mono'>{sourceCounts[name]}</strong>
            <i>
              <b
                className={`source-viz__fill source-viz__fill--${name}`}
                style={{ width: `${(sourceCounts[name] / sourceTotal) * 100}%` }}
              />
            </i>
          </button>
        ))}
      </section>
      <section className='panel panel--wide'>
        {query.error && <div className='alert alert--warning'>Live refresh paused: {query.error}</div>}
        <div className='filter-bar'>
          <label className='search-field'>
            <span>⌕</span>
            <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder='Search event, E3, node, or payload' />
          </label>
          <select value={source} onChange={(event) => setSource(event.target.value as typeof source)}>
            <option value='all'>All sources</option>
            <option value='local'>Local</option>
            <option value='network'>Network</option>
            <option value='evm'>EVM</option>
          </select>
          <select value={severity} onChange={(event) => setSeverity(event.target.value as typeof severity)}>
            <option value='all'>All levels</option>
            <option value='error'>Errors</option>
            <option value='warn'>Warnings</option>
            <option value='info'>Info</option>
            <option value='debug'>Debug</option>
          </select>
          <span className='filter-count mono'>
            {filtered.length} / {events.length}
          </span>
        </div>
        <EventTimeline events={filtered} empty='No durable events match these filters.' />
      </section>
    </div>
  )
}
