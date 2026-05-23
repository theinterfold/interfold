// SPDX-License-Identifier: LGPL-3.0-only
import { Fragment, useState } from 'react'
import type { ParsedEvent } from '../types'
import { extractType, extractE3Id, extractDetail, hlcToTime, typeSev, ERR_TYPES, WARN_TYPES, STATE_TYPES } from '../lib/events'

interface EventsTabProps {
  events: ParsedEvent[]
  cursor: number | null
  onLoadMore: () => void
}

const PAGE_SIZE = 50

type SortKey = 'seq' | 'ts' | 'type' | 'e3'
type SortDir = 'asc' | 'desc'

const SEV_OPTS = [
  { v: '', label: 'All' },
  { v: 'error', label: 'Error' },
  { v: 'warn', label: 'Warn' },
  { v: 'state', label: 'State' },
]

const SRC_OPTS = [
  { v: '', label: 'All sources' },
  { v: 'Local', label: 'Local' },
  { v: 'Net', label: 'Net' },
  { v: 'Evm', label: 'Evm' },
]

export default function EventsTab({ events, cursor, onLoadMore }: EventsTabProps) {
  const [textFilter, setTextFilter] = useState('')
  const [sevFilter, setSevFilter] = useState('')
  const [srcFilter, setSrcFilter] = useState('')
  const [sortKey, setSortKey] = useState<SortKey>('seq')
  const [sortDir, setSortDir] = useState<SortDir>('desc')
  const [page, setPage] = useState(0)
  const [openSeqs, setOpenSeqs] = useState<Set<number>>(new Set())

  function toggleOpen(seq: number) {
    setOpenSeqs((s) => {
      const n = new Set(s)
      if (n.has(seq)) n.delete(seq)
      else n.add(seq)
      return n
    })
  }

  function handleColClick(key: SortKey) {
    if (sortKey === key) setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'))
    else {
      setSortKey(key)
      setSortDir('desc')
    }
    setPage(0)
  }

  function handleFilterChange(cb: () => void) {
    cb()
    setPage(0)
  }

  const lower = textFilter.toLowerCase()
  let filtered = events.filter((e) => {
    const type = extractType(e)
    if (sevFilter) {
      const sev = typeSev(type)
      if (sevFilter === 'error' && !ERR_TYPES.includes(type)) return false
      if (sevFilter === 'warn' && !WARN_TYPES.includes(type)) return false
      if (sevFilter === 'state' && !STATE_TYPES.includes(type)) return false
      if (sevFilter !== 'error' && sevFilter !== 'warn' && sevFilter !== 'state' && sev !== sevFilter) return false
    }
    if (srcFilter && e.ctx?.source !== srcFilter) return false
    if (lower) {
      const t = type.toLowerCase()
      const e3 = (extractE3Id(e) ?? '').toLowerCase()
      if (!t.includes(lower) && !e3.includes(lower)) return false
    }
    return true
  })

  filtered = [...filtered].sort((a, b) => {
    let cmp = 0
    if (sortKey === 'seq') cmp = (a.ctx?.seq ?? 0) - (b.ctx?.seq ?? 0)
    else if (sortKey === 'ts') cmp = (a.ctx?.ts ?? '').localeCompare(b.ctx?.ts ?? '')
    else if (sortKey === 'type') cmp = extractType(a).localeCompare(extractType(b))
    else if (sortKey === 'e3') cmp = (extractE3Id(a) ?? '').localeCompare(extractE3Id(b) ?? '')
    return sortDir === 'asc' ? cmp : -cmp
  })

  const totalPages = Math.ceil(filtered.length / PAGE_SIZE)
  const slice = filtered.slice(page * PAGE_SIZE, page * PAGE_SIZE + PAGE_SIZE)

  function ColHead({ k, label }: { k: SortKey; label: string }) {
    return (
      <th className='col-head' onClick={() => handleColClick(k)}>
        {label}
        {sortKey === k && (sortDir === 'asc' ? ' ▲' : ' ▼')}
      </th>
    )
  }

  return (
    <div className='tab-pane events-pane'>
      <div className='events-toolbar'>
        <input
          className='filter-input'
          placeholder='Filter by type or E3 id…'
          value={textFilter}
          onChange={(e) => handleFilterChange(() => setTextFilter(e.target.value))}
        />
        <select className='filter-select' value={sevFilter} onChange={(e) => handleFilterChange(() => setSevFilter(e.target.value))}>
          {SEV_OPTS.map((o) => (
            <option key={o.v} value={o.v}>
              {o.label}
            </option>
          ))}
        </select>
        <select className='filter-select' value={srcFilter} onChange={(e) => handleFilterChange(() => setSrcFilter(e.target.value))}>
          {SRC_OPTS.map((o) => (
            <option key={o.v} value={o.v}>
              {o.label}
            </option>
          ))}
        </select>
        <span className='events-count'>{filtered.length} events</span>
        {cursor !== null && (
          <button className='btn-load-more' onClick={onLoadMore}>
            Load more
          </button>
        )}
      </div>

      {filtered.length === 0 ? (
        <div className='empty-state'>No events match this filter.</div>
      ) : (
        <>
          <table className='ev-table'>
            <colgroup>
              <col style={{ width: '4ch' }} />
              <col style={{ width: '7em' }} />
              <col style={{ width: '18em' }} />
              <col style={{ width: '8em' }} />
              <col />
              <col style={{ width: '4.5em' }} />
            </colgroup>
            <thead>
              <tr>
                <ColHead k='seq' label='#' />
                <ColHead k='ts' label='Time' />
                <ColHead k='type' label='Type' />
                <ColHead k='e3' label='E3' />
                <th>Detail</th>
                <th>Src</th>
              </tr>
            </thead>
            <tbody>
              {slice.map((evt) => {
                const type = extractType(evt)
                const sev = typeSev(type)
                const seq = evt.ctx?.seq ?? 0
                const open = openSeqs.has(seq)
                return (
                  <Fragment key={seq}>
                    <tr className={`ev-row sev-row-${sev || 'normal'}`} onClick={() => toggleOpen(seq)}>
                      <td className='ev-seq'>{seq}</td>
                      <td className='ev-ts'>{hlcToTime(evt.ctx?.ts)}</td>
                      <td className={`ev-type sev-${sev || 'normal'}`}>{type}</td>
                      <td className='ev-e3'>{extractE3Id(evt) ?? '—'}</td>
                      <td className='ev-detail'>{extractDetail(evt)}</td>
                      <td className={`ev-src src-${(evt.ctx?.source ?? '').toLowerCase()}`}>{evt.ctx?.source ?? ''}</td>
                    </tr>
                    {open && (
                      <tr className='ev-detail-row'>
                        <td colSpan={6}>
                          <pre className='ev-json'>{JSON.stringify(evt, null, 2)}</pre>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                )
              })}
            </tbody>
          </table>
          {totalPages > 1 && (
            <div className='pagination'>
              <button disabled={page === 0} onClick={() => setPage((p) => p - 1)}>
                ‹ Prev
              </button>
              <span>
                Page {page + 1} / {totalPages}
              </span>
              <button disabled={page >= totalPages - 1} onClick={() => setPage((p) => p + 1)}>
                Next ›
              </button>
            </div>
          )}
        </>
      )}
    </div>
  )
}
