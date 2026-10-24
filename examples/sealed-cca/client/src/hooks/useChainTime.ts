// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useEffect, useState } from 'react'
import { publicClient } from '@/utils/chain'

const SYNC_MS = 15_000

/**
 * The chain's clock in unix seconds, ticking every second. Input windows are enforced against block
 * timestamps, so the UI counts down against the chain, not the browser clock: the clock is read from
 * the latest block now and then and extrapolated with the browser's elapsed time in between. A chain
 * that is behind the wall clock only because no block was mined recently is treated as in sync.
 */
export function useChainTime(): bigint {
  const [now, setNow] = useState(() => BigInt(Math.floor(Date.now() / 1000)))

  useEffect(() => {
    let offsetSeconds = 0
    let cancelled = false

    const sync = async () => {
      try {
        const block = await publicClient.getBlock()
        if (cancelled) return
        offsetSeconds = Math.max(Number(block.timestamp) - Date.now() / 1000, 0)
      } catch (err) {
        console.warn('Could not read the chain time:', err)
      }
    }
    const tick = () => setNow(BigInt(Math.floor(Date.now() / 1000 + offsetSeconds)))

    void sync().then(tick)
    const syncTimer = setInterval(() => void sync(), SYNC_MS)
    const tickTimer = setInterval(tick, 1000)
    return () => {
      cancelled = true
      clearInterval(syncTimer)
      clearInterval(tickTimer)
    }
  }, [])

  return now
}
