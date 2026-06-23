// SPDX-License-Identifier: LGPL-3.0-only

import { useMemo, useState } from 'react'
import { useLogs } from '../api'
import { short } from '../format'

export default function LogsView() {
  const logs = useLogs()
  const [search, setSearch] = useState('')
  const [level, setLevel] = useState('all')
  const levelCounts = useMemo(() => {
    const counts = new Map<string, number>()
    for (const entry of logs.data?.entries ?? []) counts.set(entry.level.toLowerCase(), (counts.get(entry.level.toLowerCase()) ?? 0) + 1)
    const maximum = Math.max(1, ...counts.values())
    return ['error', 'warn', 'info', 'debug', 'trace'].map((name) => ({ name, count: counts.get(name) ?? 0, maximum }))
  }, [logs.data?.entries])
  const entries = useMemo(() => {
    const needle = search.toLowerCase().trim()
    return (logs.data?.entries ?? [])
      .filter((entry) => {
        if (level !== 'all' && entry.level.toLowerCase() !== level) return false
        return !needle || `${entry.message} ${entry.target} ${JSON.stringify(entry.fields ?? {})}`.toLowerCase().includes(needle)
      })
      .reverse()
  }, [level, logs.data?.entries, search])
  return (
    <div className='view-stack'>
      <header className='view-title'>
        <div>
          <span className='section-kicker'>Operational diagnostics</span>
          <h1>Ciphernode logs</h1>
          <p>
            Structured tracing output for networking, RPC, proving, startup, and resource diagnostics. Protocol facts live in EventStore.
          </p>
        </div>
      </header>
      <section className='panel log-viz' aria-label='Log level distribution'>
        <div>
          <span className='section-kicker'>Current memory window</span>
          <h2>Signal distribution</h2>
        </div>
        <div className='log-viz__bars'>
          {levelCounts.map((item) => (
            <div key={item.name}>
              <span>{item.name}</span>
              <i>
                <b className={`log-viz__bar log-viz__bar--${item.name}`} style={{ width: `${(item.count / item.maximum) * 100}%` }} />
              </i>
              <strong className='mono'>{item.count}</strong>
            </div>
          ))}
        </div>
      </section>
      <section className='panel panel--wide'>
        <div className='filter-bar'>
          <label className='search-field'>
            <span>⌕</span>
            <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder='Search messages, targets, and fields' />
          </label>
          <select value={level} onChange={(event) => setLevel(event.target.value)}>
            <option value='all'>All levels</option>
            <option value='error'>Error</option>
            <option value='warn'>Warn</option>
            <option value='info'>Info</option>
            <option value='debug'>Debug</option>
            <option value='trace'>Trace</option>
          </select>
          <span className='filter-count mono'>
            {entries.length} visible · {logs.data?.total_stored ?? 0} stored
          </span>
        </div>
        {logs.error && <div className='alert alert--warning'>{logs.error}</div>}
        <div className='log-table'>
          <div className='log-table__head'>
            <span>Time</span>
            <span>Level</span>
            <span>Target</span>
            <span>Message</span>
          </div>
          {entries.map((entry) => (
            <details className={`log-row log-row--${entry.level.toLowerCase()}`} key={entry.seq}>
              <summary>
                <time className='mono'>{new Date(entry.timestamp_ms).toLocaleTimeString()}</time>
                <span className='log-level'>{entry.level}</span>
                <span className='mono' title={entry.target}>
                  {short(entry.target, 24, 10)}
                </span>
                <strong>{entry.message}</strong>
              </summary>
              {(entry.fields?.e3_id || entry.fields?.event_id || entry.fields?.stage) && (
                <div className='log-trace-context'>
                  {entry.fields.stage && (
                    <span>
                      stage <strong>{String(entry.fields.stage)}</strong>
                    </span>
                  )}
                  {entry.fields.e3_id && (
                    <span>
                      E3 <strong className='mono'>{String(entry.fields.e3_id)}</strong>
                    </span>
                  )}
                  {entry.fields.event_id && (
                    <span>
                      event <strong className='mono'>{String(entry.fields.event_id)}</strong>
                    </span>
                  )}
                </div>
              )}
              <pre>{JSON.stringify(entry.fields ?? {}, null, 2)}</pre>
            </details>
          ))}
          {!entries.length && <div className='empty-inline'>No operational logs match these filters.</div>}
        </div>
      </section>
    </div>
  )
}
