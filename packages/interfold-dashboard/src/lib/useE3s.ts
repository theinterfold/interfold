// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
// React hooks wrapping the on-chain fetchers. Polls every POLL_MS while mounted.

import { useEffect, useRef, useState } from 'react'
import { fetchE3Details, fetchE3List, fetchRecentBallotCount, type E3FullDetails, type E3Summary } from './e3'

const POLL_MS = 15_000

export type LoadState<T> =
  | { status: 'loading'; data: null; error: null }
  | { status: 'ready'; data: T; error: null }
  | { status: 'error'; data: null; error: Error }

function useE3List(crispOnly: boolean): LoadState<E3Summary[]> {
  const [state, setState] = useState<LoadState<E3Summary[]>>({
    status: 'loading',
    data: null,
    error: null,
  })
  const mounted = useRef(true)

  useEffect(() => {
    mounted.current = true
    let cancelled = false
    let inFlight = false

    const tick = async () => {
      if (inFlight) return // skip if a slow fetch is still running
      inFlight = true
      try {
        const list = await fetchE3List({ crispOnly })
        if (!cancelled && mounted.current) {
          setState({ status: 'ready', data: list, error: null })
        }
      } catch (e: any) {
        if (!cancelled && mounted.current) {
          setState((prev) => (prev.status === 'ready' ? prev : { status: 'error', data: null, error: e }))
        }
      } finally {
        inFlight = false
      }
    }
    tick()
    const id = setInterval(tick, POLL_MS)
    return () => {
      cancelled = true
      mounted.current = false
      clearInterval(id)
    }
  }, [crispOnly])

  return state
}

// CRISP poll view — every CRISP-program E3 (newest featured, the rest archived).
export function useCrispPolls(): LoadState<E3Summary[]> {
  return useE3List(true)
}

// Generic E3 inspector — every E3 on the network, any program.
export function useAllE3s(): LoadState<E3Summary[]> {
  return useE3List(false)
}

// CRISP ballots submitted in roughly the last 24h (0 until first load).
export function useRecentBallots(): number {
  const [count, setCount] = useState(0)
  const mounted = useRef(true)

  useEffect(() => {
    mounted.current = true
    let cancelled = false
    let inFlight = false
    const tick = async () => {
      if (inFlight) return
      inFlight = true
      try {
        const n = await fetchRecentBallotCount()
        if (!cancelled && mounted.current) setCount(n)
      } catch {
        /* keep last value on transient errors */
      } finally {
        inFlight = false
      }
    }
    tick()
    const id = setInterval(tick, POLL_MS)
    return () => {
      cancelled = true
      mounted.current = false
      clearInterval(id)
    }
  }, [])

  return count
}

export function useE3Details(e3Id: bigint | null): LoadState<E3FullDetails> {
  const [state, setState] = useState<LoadState<E3FullDetails>>({
    status: 'loading',
    data: null,
    error: null,
  })
  const mounted = useRef(true)
  const e3IdKey = e3Id?.toString() ?? null

  useEffect(() => {
    mounted.current = true
    // Reset to loading whenever the selected E3 changes so the UI shows a
    // spinner instead of the previous E3's (stale) data while the new one loads.
    setState({ status: 'loading', data: null, error: null })
    if (e3Id === null) {
      return
    }
    let cancelled = false
    let inFlight = false

    const tick = async () => {
      if (inFlight) return // skip if a slow fetch is still running
      inFlight = true
      try {
        const detail = await fetchE3Details(e3Id)
        if (!cancelled && mounted.current) {
          setState({ status: 'ready', data: detail, error: null })
        }
      } catch (e: any) {
        if (!cancelled && mounted.current) {
          setState((prev) => (prev.status === 'ready' ? prev : { status: 'error', data: null, error: e }))
        }
      } finally {
        inFlight = false
      }
    }
    tick()
    const id = setInterval(tick, POLL_MS)
    return () => {
      cancelled = true
      mounted.current = false
      clearInterval(id)
    }
    // e3Id is captured via its stable string key; re-run when that changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [e3IdKey])

  return state
}
