// SPDX-License-Identifier: LGPL-3.0-only
import { useCallback, useEffect, useRef, useState } from 'react'
import type { ArchivePage, PollRequestResult } from '@/model/poll.model'

type FetchPage = (cursor?: string) => Promise<ArchivePage | undefined>

export function useArchivePolls(fetchPage: FetchPage) {
  const [items, setItems] = useState<PollRequestResult[]>([])
  const [hasMore, setHasMore] = useState(true)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const state = useRef({ pending: false, cursor: undefined as string | undefined, done: false })

  const loadMore = useCallback(async () => {
    const current = state.current
    if (current.pending || current.done) return
    current.pending = true
    setIsLoading(true)
    setError(null)
    try {
      const page = await fetchPage(current.cursor)
      if (state.current !== current) return
      if (!page) throw new Error('Archive response is missing')
      if (page.next_cursor !== null && page.next_cursor === current.cursor) throw new Error('Archive cursor did not advance')
      setItems((previous) => {
        const rows = new Map(previous.map((item) => [item.round_id, item]))
        for (const item of page.items) rows.set(item.round_id, item)
        return [...rows.values()]
      })
      current.cursor = page.next_cursor ?? undefined
      current.done = page.next_cursor === null
      setHasMore(!current.done)
    } catch {
      if (state.current === current) setError('Could not load polls. Try again.')
    } finally {
      current.pending = false
      if (state.current === current) setIsLoading(false)
    }
  }, [fetchPage])

  useEffect(() => {
    state.current = { pending: false, cursor: undefined, done: false }
    // Clear the old query result when the data source changes.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setItems([])
    setHasMore(true)
    void loadMore()
    return () => {
      state.current = { pending: false, cursor: undefined, done: true }
    }
  }, [loadMore])

  return { items, hasMore, isLoading, error, loadMore }
}
