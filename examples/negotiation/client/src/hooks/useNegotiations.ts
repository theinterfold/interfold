// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useCallback, useEffect, useRef, useState } from 'react'
import { type NegotiationState, listNegotiationIds, loadNegotiation } from '@/utils/negotiation'
import { formatError } from '@/utils/error-formatting'

const LIST_POLL_MS = 10_000
const NEGOTIATION_POLL_MS = 4_000

export interface Loaded<T> {
  data: T
  loading: boolean
  error: string | null
}

/** Every negotiation, newest first, refreshed while the page is open. */
export function useNegotiations(): Loaded<NegotiationState[]> {
  const [state, setState] = useState<Loaded<NegotiationState[]>>({ data: [], loading: true, error: null })

  useEffect(() => {
    let cancelled = false
    const load = async () => {
      try {
        const ids = await listNegotiationIds()
        const negotiations = await Promise.all(ids.map((id) => loadNegotiation(id)))
        if (!cancelled) {
          setState({ data: negotiations.filter((item): item is NegotiationState => item !== null), loading: false, error: null })
        }
      } catch (err) {
        if (!cancelled) setState((prev) => ({ ...prev, loading: false, error: formatError(err) }))
      }
    }
    void load()
    const timer = setInterval(() => void load(), LIST_POLL_MS)
    return () => {
      cancelled = true
      clearInterval(timer)
    }
  }, [])

  return state
}

export interface NegotiationView {
  /** `undefined` until the first read, `null` if the program has no such negotiation. */
  negotiation: NegotiationState | null | undefined
  error: string | null
  refresh: () => Promise<void>
}

/** One negotiation, polled for stage, offers and outcome. */
export function useNegotiation(e3Id: bigint | null): NegotiationView {
  const [negotiation, setNegotiation] = useState<NegotiationState | null | undefined>(undefined)
  const [error, setError] = useState<string | null>(null)
  const latest = useRef(e3Id)

  const refresh = useCallback(async () => {
    const id = latest.current
    if (id === null) return
    try {
      const next = await loadNegotiation(id)
      // A slow read of an earlier negotiation must not overwrite the one on screen now.
      if (latest.current !== id) return
      setNegotiation(next)
      setError(null)
    } catch (err) {
      // The node may be restarting; keep the last known state and try again.
      if (latest.current === id) setError(formatError(err))
    }
  }, [])

  useEffect(() => {
    latest.current = e3Id
    setNegotiation(undefined)
    setError(null)
    if (e3Id === null) return
    void refresh()
    const timer = setInterval(() => void refresh(), NEGOTIATION_POLL_MS)
    return () => clearInterval(timer)
  }, [e3Id, refresh])

  return { negotiation, error, refresh }
}
