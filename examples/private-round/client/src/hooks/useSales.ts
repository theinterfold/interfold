// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useCallback, useEffect, useRef, useState } from 'react'
import { type SaleState, listSaleIds, loadSale } from '@/utils/sale'
import { formatError } from '@/utils/error-formatting'

const LIST_POLL_MS = 10_000
const SALE_POLL_MS = 4_000

export interface Loaded<T> {
  data: T
  loading: boolean
  error: string | null
}

/** Every sale, newest first, refreshed while the page is open. */
export function useSales(): Loaded<SaleState[]> {
  const [state, setState] = useState<Loaded<SaleState[]>>({ data: [], loading: true, error: null })

  useEffect(() => {
    let cancelled = false
    const load = async () => {
      try {
        const ids = await listSaleIds()
        const sales = await Promise.all(ids.map((id) => loadSale(id)))
        if (!cancelled) setState({ data: sales.filter((sale): sale is SaleState => sale !== null), loading: false, error: null })
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

export interface SaleView {
  /** `undefined` until the first read, `null` if the program has no such sale. */
  sale: SaleState | null | undefined
  error: string | null
  refresh: () => Promise<void>
}

/** One sale, polled for stage and bidder count. */
export function useSale(e3Id: bigint | null): SaleView {
  const [sale, setSale] = useState<SaleState | null | undefined>(undefined)
  const [error, setError] = useState<string | null>(null)
  const latest = useRef(e3Id)

  const refresh = useCallback(async () => {
    const id = latest.current
    if (id === null) return
    try {
      const next = await loadSale(id)
      // A slow read of an earlier sale must not overwrite the one on screen now.
      if (latest.current !== id) return
      setSale(next)
      setError(null)
    } catch (err) {
      // The node may be restarting; keep the last known state and try again.
      if (latest.current === id) setError(formatError(err))
    }
  }, [])

  useEffect(() => {
    latest.current = e3Id
    setSale(undefined)
    setError(null)
    if (e3Id === null) return
    void refresh()
    const timer = setInterval(() => void refresh(), SALE_POLL_MS)
    return () => clearInterval(timer)
  }, [e3Id, refresh])

  return { sale, error, refresh }
}
