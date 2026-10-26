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

const POLL_MS = 10_000

/** What has left the program after the sale ended, from the events of the refund and withdraw actions. */
export interface Settlement {
  /** Bid indexes whose escrow went back to the bidder (dropped bids and refunds of a stopped sale). */
  refunded: ReadonlySet<number>
  swept: { saleTokens: bigint; paymentTokens: bigint } | null
  unsoldWithdrawn: boolean
  supplyRefunded: boolean
  forfeitedWithdrawn: boolean
}

export interface UseSettlement {
  /** `null` before the first read. */
  settlement: Settlement | null
  refresh: () => void
}

/** The refunds and the creator withdrawals of a sale. Read while `enabled`, that is once the sale has ended. */
export function useSettlement(saleId: bigint, enabled: boolean): UseSettlement {
  const [settlement, setSettlement] = useState<Settlement | null>(null)
  const latest = useRef(saleId)

  const refresh = useCallback(() => {
    const id = latest.current
    const { e3Program } = getContractAddresses()
    const base = { address: e3Program, abi: TokenLaunchProgram__factory.abi, args: { saleId: id }, strict: true } as const
    const events = <T>(read: (range: { fromBlock: bigint; toBlock: bigint }) => Promise<T[]>) => scanLogs(read).then(({ logs }) => logs)
    Promise.all([
      events((range) => publicClient.getContractEvents({ ...base, eventName: 'DroppedRefunded', ...range })),
      events((range) => publicClient.getContractEvents({ ...base, eventName: 'EscrowRefunded', ...range })),
      events((range) => publicClient.getContractEvents({ ...base, eventName: 'Swept', ...range })),
      events((range) => publicClient.getContractEvents({ ...base, eventName: 'UnsoldWithdrawn', ...range })),
      events((range) => publicClient.getContractEvents({ ...base, eventName: 'SupplyRefunded', ...range })),
      events((range) => publicClient.getContractEvents({ ...base, eventName: 'ForfeitedWithdrawn', ...range })),
    ])
      .then(([dropped, escrow, swept, unsold, supply, forfeited]) => {
        if (latest.current !== id) return
        const sweep = swept.at(-1)
        setSettlement({
          refunded: new Set([...dropped, ...escrow].map((log) => Number(log.args.index))),
          swept: sweep ? { saleTokens: sweep.args.saleTokens, paymentTokens: sweep.args.paymentTokens } : null,
          unsoldWithdrawn: unsold.length > 0,
          supplyRefunded: supply.length > 0,
          forfeitedWithdrawn: forfeited.length > 0,
        })
      })
      .catch((err) => console.warn('Could not read the refunds:', err))
  }, [])

  useEffect(() => {
    latest.current = saleId
    setSettlement(null)
    if (!enabled) return
    refresh()
    const timer = setInterval(refresh, POLL_MS)
    return () => clearInterval(timer)
  }, [saleId, enabled, refresh])

  return { settlement, refresh }
}
