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
  return response.json() as Promise<T>
}

export function useSnapshot(intervalMs = 2_000): QueryState<DashboardSnapshot> {
  const [state, setState] = useState<QueryState<DashboardSnapshot>>({ loading: true })

  useEffect(() => {
    let active = true
    let controller: AbortController | undefined
    let refreshing = false
    const refresh = async () => {
      if (refreshing) return
      refreshing = true
      controller = new AbortController()
      try {
        const data = await getJson<DashboardSnapshot>('/api/snapshot', controller.signal)
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
  }, [intervalMs])

  return state
}

export function useE3Trace(e3Id?: string, refreshKey = 0): QueryState<E3Trace> {
  const [state, setState] = useState<QueryState<E3Trace>>({ loading: Boolean(e3Id) })

  useEffect(() => {
    if (!e3Id) {
      setState({ loading: false })
      return
    }
    const controller = new AbortController()
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

  return state
}

export function useLogs(intervalMs = 2_000): QueryState<LogResponse> {
  const [state, setState] = useState<QueryState<LogResponse>>({ loading: true })
  useEffect(() => {
    let active = true
    const refresh = () => {
      getJson<LogResponse>('/api/logs?limit=2000')
        .then((data) => {
          if (active) setState({ data, loading: false })
        })
        .catch((error) => {
          if (active)
            setState((previous) => ({ ...previous, error: error instanceof Error ? error.message : String(error), loading: false }))
        })
    }
    refresh()
    const timer = window.setInterval(refresh, intervalMs)
    return () => {
      active = false
      window.clearInterval(timer)
    }
  }, [intervalMs])
  return state
}

export function useEvents(intervalMs = 2_500): QueryState<EventsResponse> {
  const [state, setState] = useState<QueryState<EventsResponse>>({ loading: true })
  useEffect(() => {
    let active = true
    const refresh = () => {
      getJson<EventsResponse>('/api/events?limit=2000')
        .then((data) => {
          if (active) setState({ data, loading: false })
        })
        .catch((error) => {
          if (active)
            setState((previous) => ({ ...previous, error: error instanceof Error ? error.message : String(error), loading: false }))
        })
    }
    refresh()
    const timer = window.setInterval(refresh, intervalMs)
    return () => {
      active = false
      window.clearInterval(timer)
    }
  }, [intervalMs])
  return state
}

export function useUpdates(intervalMs = 60 * 60 * 1_000): QueryState<UpdateSnapshot> {
  const [state, setState] = useState<QueryState<UpdateSnapshot>>({ loading: true })
  useEffect(() => {
    let active = true
    const refresh = () => {
      getJson<UpdateSnapshot>('/api/updates')
        .then((data) => {
          if (active) setState({ data, loading: false })
        })
        .catch((error) => {
          if (active)
            setState((previous) => ({ ...previous, error: error instanceof Error ? error.message : String(error), loading: false }))
        })
    }
    refresh()
    const timer = window.setInterval(refresh, intervalMs)
    return () => {
      active = false
      window.clearInterval(timer)
    }
  }, [intervalMs])
  return state
}
