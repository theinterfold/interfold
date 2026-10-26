// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useCallback, useEffect, useRef, useState } from 'react'
import { TokenLaunchProgram__factory } from '@contract-types/factories/contracts/TokenLaunchProgram__factory'
import { publicClient } from '@/utils/chain'
import { getContractAddresses } from '@/utils/env-config'
import { scanLogs } from '@/utils/logs'

const POLL_MS = 5_000

/** A bid as the `BidSubmitted` event shows it. The ciphertexts are left out: the page does not need them. */
export interface LoggedBid {
  index: number
  bidder: `0x${string}`
  tier: number
  bidCommitment: `0x${string}`
  txHash: `0x${string}`
}

/** Bids found so far for each sale, and the block they are complete up to: later scans resume from there. */
const cache = new Map<string, { bids: Map<number, LoggedBid>; scannedTo: bigint | null }>()

/** Every bid of the sale, ascending by index, from the `BidSubmitted` logs. */
export async function fetchBids(saleId: bigint): Promise<LoggedBid[]> {
  const { e3Program } = getContractAddresses()
  const entry = cache.get(saleId.toString()) ?? { bids: new Map<number, LoggedBid>(), scannedTo: null }
  cache.set(saleId.toString(), entry)
  const { logs, head } = await scanLogs(
    (range) =>
      publicClient.getContractEvents({
        address: e3Program,
        abi: TokenLaunchProgram__factory.abi,
        eventName: 'BidSubmitted',
        args: { saleId },
        strict: true,
        ...range,
      }),
    entry.scannedTo === null ? undefined : entry.scannedTo + 1n,
  )
  for (const log of logs) {
    const { index, bidder, tier, bidCommitment } = log.args
    entry.bids.set(Number(index), { index: Number(index), bidder, tier, bidCommitment, txHash: log.transactionHash })
  }
  entry.scannedTo = head
  return [...entry.bids.values()].sort((a, b) => a.index - b.index)
}

/** The bids of a sale, refreshed while `poll` is true. `null` before the first read. */
export function useBidLog(saleId: bigint | null, poll: boolean): { bids: LoggedBid[] | null; refresh: () => void } {
  const [bids, setBids] = useState<LoggedBid[] | null>(null)
  const latest = useRef(saleId)

  const refresh = useCallback(() => {
    const id = latest.current
    if (id === null) return
    fetchBids(id)
      .then((next) => {
        if (latest.current === id) setBids(next)
      })
      .catch((err) => console.warn('Could not read the bids:', err))
  }, [])

  useEffect(() => {
    latest.current = saleId
    setBids(null)
    if (saleId === null) return
    refresh()
    if (!poll) return
    const timer = setInterval(refresh, POLL_MS)
    return () => clearInterval(timer)
  }, [saleId, poll, refresh])

  return { bids, refresh }
}
