// SPDX-License-Identifier: LGPL-3.0-only
import { useCallback, useEffect, useRef, useState } from 'react'
import type { ParsedEvent } from '../types'
import { api } from '../lib/api'
import { parseNdjsonResponse } from '../lib/events'

export interface UseEventsResult {
  allEvents: ParsedEvent[]
  eventCursor: number | null
  connected: boolean | null // null = initial connecting
  loadMore: () => Promise<void>
}

export function useEvents(): UseEventsResult {
  // Mutable refs (don't trigger re-renders on their own)
  const allEventsRef = useRef<ParsedEvent[]>([])
  const seenIdsRef = useRef<Set<string>>(new Set())
  const perAggregateMaxSeqRef = useRef<Map<number, number>>(new Map())
  const isPollingRef = useRef(false)

  // State that drives UI updates
  const [_version, setVersion] = useState(0)
  const [eventCursor, setEventCursor] = useState<number | null>(null)
  const [connected, setConnected] = useState<boolean | null>(null)

  const forceUpdate = useCallback(() => setVersion((v) => v + 1), [])

  const loadEvents = useCallback(async (since: number, append: boolean): Promise<void> => {
    const text = await api(`/api/events?since=${since}&limit=500`)
    if (!append) {
      allEventsRef.current = []
      seenIdsRef.current = new Set()
      perAggregateMaxSeqRef.current = new Map()
    }

    const { events, cursor, perAggregateMaxSeq } = parseNdjsonResponse(text, seenIdsRef.current)

    // Merge per-aggregate max seqs (always, even for duplicate events already filtered)
    for (const [aggId, seq] of perAggregateMaxSeq) {
      const prev = perAggregateMaxSeqRef.current.get(aggId) ?? 0
      if (seq > prev) perAggregateMaxSeqRef.current.set(aggId, seq)
    }

    if (events.length > 0) {
      allEventsRef.current = allEventsRef.current.concat(events)
    }

    setEventCursor(cursor)
  }, [])

  const loadMore = useCallback(async () => {
    const cur = eventCursor
    if (cur == null) return
    try {
      await loadEvents(cur, true)
      forceUpdate()
    } catch {
      // swallow
    }
  }, [eventCursor, loadEvents, forceUpdate])

  useEffect(() => {
    let alive = true

    async function poll() {
      if (!alive || isPollingRef.current) return
      isPollingRef.current = true
      // Use the minimum per-aggregate seq as the global since cursor.
      // This ensures we don't advance past any store that may have fewer events,
      // while ID-based dedup handles re-received events from more-advanced stores.
      const perAgg = perAggregateMaxSeqRef.current
      const since = perAgg.size === 0 ? 0 : Math.min(...perAgg.values())
      const append = since > 0 || allEventsRef.current.length > 0
      try {
        await loadEvents(since, append)
        if (alive) {
          setConnected(true)
          forceUpdate()
        }
      } catch {
        if (alive) setConnected(false)
      } finally {
        isPollingRef.current = false
      }
    }

    poll()
    const id = setInterval(poll, 5000)
    return () => {
      alive = false
      clearInterval(id)
    }
  }, [loadEvents, forceUpdate])

  // Expose a stable snapshot (always current on each render triggered by forceUpdate)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  return { allEvents: allEventsRef.current, eventCursor, connected, loadMore }
}
