// SPDX-License-Identifier: LGPL-3.0-only

import { useEffect, useState } from 'react'
import type { DashboardSnapshot, E3Trace, EventsResponse, LogResponse, UpdateSnapshot } from './types'

export interface QueryState<T> {
  data?: T
  error?: string
  loading: boolean
}

async function getJson<T>(path: string, signal?: AbortSignal): Promise<T> {
  const response = await fetch(path, { signal, cache: 'no-store' })
  if (!response.ok) {
    const detail = await response.json().catch(() => null)
    throw new Error(detail?.error ?? `${response.status} ${response.statusText}`)
  }
  try {
    return (await response.json()) as T
  } catch {
    throw new Error(`Invalid JSON in response from ${path}`)
  }
}

/**
 * Polls a JSON endpoint on an interval with an abort on unmount, a
 * re-entrancy guard so a slow endpoint can't stack overlapping requests, and a
 * visibility check so background tabs don't poll.
 */
function usePolledJson<T>(path: string, intervalMs: number): QueryState<T> {
  const [state, setState] = useState<QueryState<T>>({ loading: true })

  useEffect(() => {
    let active = true
    let controller: AbortController | undefined
    let refreshing = false
    const refresh = async () => {
      if (refreshing) return
      refreshing = true
      controller = new AbortController()
      try {
        const data = await getJson<T>(path, controller.signal)
        if (active) setState({ data, loading: false })
      } catch (error) {
        if (active && !(error instanceof DOMException && error.name === 'AbortError')) {
          setState((previous) => ({ ...previous, error: error instanceof Error ? error.message : String(error), loading: false }))
        }
      } finally {
        refreshing = false
      }
    }
    void refresh()
    const timer = window.setInterval(() => {
      if (document.visibilityState === 'visible') void refresh()
    }, intervalMs)
    return () => {
      active = false
      controller?.abort()
      window.clearInterval(timer)
    }
  }, [path, intervalMs])

  return state
}

export function useSnapshot(intervalMs = 2_000): QueryState<DashboardSnapshot> {
  return usePolledJson<DashboardSnapshot>('/api/snapshot', intervalMs)
}

export function useE3Trace(e3Id?: string, refreshKey = 0): QueryState<E3Trace> {
  const [state, setState] = useState<QueryState<E3Trace>>({ loading: Boolean(e3Id) })

  useEffect(() => {
    if (!e3Id) return
    const controller = new AbortController()
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setState((previous) => ({ ...previous, loading: !previous.data }))
    getJson<E3Trace>(`/api/e3?e3_id=${encodeURIComponent(e3Id)}`, controller.signal)
      .then((data) => setState({ data, loading: false }))
      .catch((error) => {
        if (!(error instanceof DOMException && error.name === 'AbortError')) {
          setState((previous) => ({ ...previous, error: error instanceof Error ? error.message : String(error), loading: false }))
        }
      })
    return () => controller.abort()
  }, [e3Id, refreshKey])

  if (!e3Id) return { loading: false }
  return state
}

export function useLogs(intervalMs = 2_000): QueryState<LogResponse> {
  return usePolledJson<LogResponse>('/api/logs?limit=2000', intervalMs)
}

export function useEvents(intervalMs = 2_500): QueryState<EventsResponse> {
  return usePolledJson<EventsResponse>('/api/events?limit=2000', intervalMs)
}

export function useUpdates(intervalMs = 60 * 60 * 1_000): QueryState<UpdateSnapshot> {
  return usePolledJson<UpdateSnapshot>('/api/updates', intervalMs)
}
