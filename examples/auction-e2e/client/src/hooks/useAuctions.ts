// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useCallback, useEffect, useRef, useState } from 'react'
import { type AuctionState, listAuctionIds, loadAuction } from '@/utils/auction'
import { formatError } from '@/utils/error-formatting'

const LIST_POLL_MS = 10_000
const AUCTION_POLL_MS = 4_000

export interface Loaded<T> {
  data: T
  loading: boolean
  error: string | null
}

/** Every auction, newest first, refreshed while the page is open. */
export function useAuctions(): Loaded<AuctionState[]> {
  const [state, setState] = useState<Loaded<AuctionState[]>>({ data: [], loading: true, error: null })

  useEffect(() => {
    let cancelled = false
    const load = async () => {
      try {
        const ids = await listAuctionIds()
        const auctions = await Promise.all(ids.map((id) => loadAuction(id)))
        if (!cancelled)
          setState({ data: auctions.filter((auction): auction is AuctionState => auction !== null), loading: false, error: null })
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

export interface AuctionView {
  /** `undefined` until the first read, `null` if the program has no such auction. */
  auction: AuctionState | null | undefined
  error: string | null
  refresh: () => Promise<void>
}

/** One auction, polled for stage and bidder count. */
export function useAuction(e3Id: bigint | null): AuctionView {
  const [auction, setAuction] = useState<AuctionState | null | undefined>(undefined)
  const [error, setError] = useState<string | null>(null)
  const latest = useRef(e3Id)
  latest.current = e3Id

  const refresh = useCallback(async () => {
    const id = latest.current
    if (id === null) return
    try {
      const next = await loadAuction(id)
      // A slow read of an earlier auction must not overwrite the one on screen now.
      if (latest.current !== id) return
      setAuction(next)
      setError(null)
    } catch (err) {
      // The node may be restarting; keep the last known state and try again.
      if (latest.current === id) setError(formatError(err))
    }
  }, [])

  useEffect(() => {
    setAuction(undefined)
    setError(null)
    if (e3Id === null) return
    void refresh()
    const timer = setInterval(() => void refresh(), AUCTION_POLL_MS)
    return () => clearInterval(timer)
  }, [e3Id, refresh])

  return { auction, error, refresh }
}
