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

/** The roles (a bitmask, bit `role`) that `account` has submitted in the auction, or `null` before the first read. */
export function useSubmittedRoles(e3Id: bigint | null, account: `0x${string}` | undefined): { mask: number | null; refresh: () => void } {
  const [mask, setMask] = useState<number | null>(null)
  const target = useRef({ e3Id, account })
  target.current = { e3Id, account }

  const refresh = useCallback(() => {
    const { e3Id: id, account: bidder } = target.current
    if (id === null || !bidder) return
    const { e3Program } = getContractAddresses()
    publicClient
      .readContract({ address: e3Program, abi: AuctionProgram__factory.abi, functionName: 'submittedRoles', args: [id, bidder] })
      .then((value) => {
        if (target.current.e3Id === id && target.current.account === bidder) setMask(value)
      })
      .catch((err) => console.warn('Could not read the submitted roles:', err))
  }, [])

  useEffect(() => {
    setMask(null)
    if (e3Id === null || !account) return
    refresh()
    const timer = setInterval(refresh, POLL_MS)
    return () => clearInterval(timer)
  }, [e3Id, account, refresh])

  return { mask, refresh }
}
