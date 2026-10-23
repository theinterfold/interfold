// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useCallback, useEffect, useRef, useState } from 'react'
import { AuctionProgram__factory } from '@contract-types/factories/contracts/AuctionProgram__factory'
import { publicClient } from '@/utils/chain'
import { getContractAddresses } from '@/utils/env-config'

const POLL_MS = 5_000

/** How many bids (the first one and its updates) `account` has on chain in the auction, or `null` before the first read. */
export function useBidCount(e3Id: bigint | null, account: `0x${string}` | undefined): { count: number | null; refresh: () => void } {
  const [count, setCount] = useState<number | null>(null)
  const target = useRef({ e3Id, account })

  const refresh = useCallback(() => {
    const { e3Id: id, account: bidder } = target.current
    if (id === null || !bidder) return
    const { e3Program } = getContractAddresses()
    publicClient
      .readContract({ address: e3Program, abi: AuctionProgram__factory.abi, functionName: 'bidCount', args: [id, bidder] })
      .then((value) => {
        if (target.current.e3Id === id && target.current.account === bidder) setCount(value)
      })
      .catch((err) => console.warn('Could not read the bid count:', err))
  }, [])

  useEffect(() => {
    target.current = { e3Id, account }
    setCount(null)
    if (e3Id === null || !account) return
    refresh()
    const timer = setInterval(refresh, POLL_MS)
    return () => clearInterval(timer)
  }, [e3Id, account, refresh])

  return { count, refresh }
}
