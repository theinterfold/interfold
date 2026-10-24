// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useCallback, useEffect, useRef, useState } from 'react'
import { useWalletClient } from 'wagmi'
import { decodeOutput } from '@interfold/sealed-cca'
import { SealedCcaProgram__factory } from '@contract-types/factories/contracts/SealedCcaProgram__factory'
import { chain, publicClient } from '@/utils/chain'
import { getContractAddresses } from '@/utils/env-config'
import { formatError } from '@/utils/error-formatting'
import { scanLogs } from '@/utils/logs'
import type { SaleState } from '@/utils/sale'

const POLL_MS = 5_000

export type ClearingKind = 'undersubscribed' | 'capped' | 'uncapped'

/** The kind codes of the contract: `clearing` returns 0, 1 or 2. */
const KINDS: readonly ClearingKind[] = ['undersubscribed', 'capped', 'uncapped']

/** The clearing of a sale as the contract computed it from the decrypted demand curve. */
export interface Clearing {
  kind: ClearingKind
  /** `k` of the claim proof: `s` for a capped sale, `l` for an uncapped one. Zero when undersubscribed. */
  step: number
  /** The uniform price in payment-token base units per whole sale token (between two steps when uncapped). */
  pStar: bigint
  /** Sale-token base units that a full winner gets. */
  fullTokens: bigint
  /** Sale-token base units that each bidder at the marginal step gets (capped sales). */
  marginalTokens: bigint
  /** Sale-token base units sold in all. */
  soldTotal: bigint
  /** Unix seconds: the last second at which `claim` works. After it the creator can sweep what is left. */
  claimDeadline: bigint
}

export interface UseClearing {
  /** `c_l`, the bidders whose price is at or above step `l`: from the `SaleCleared` event once cleared, else decoded from the published output. */
  counts: bigint[] | null
  /** `null` until the sale is cleared on chain. */
  clearing: Clearing | null
  clear: () => Promise<void>
  clearBusy: boolean
  error: string | null
  refresh: () => void
}

/** The demand curve and the clearing of a sale whose output is published. Anyone can send the `clear` transaction. */
export function useClearing(sale: SaleState): UseClearing {
  const { data: walletClient } = useWalletClient({ chainId: chain.id })
  const { e3Program } = getContractAddresses()
  const [counts, setCounts] = useState<bigint[] | null>(null)
  const [clearing, setClearing] = useState<Clearing | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const countsFromEvent = useRef(false)
  const output = sale.plaintextOutput
  const e3Id = sale.e3Id

  // The demand curve is readable as soon as the output is published.
  useEffect(() => {
    setCounts(null)
    if (output === null) return
    let cancelled = false
    decodeOutput(output)
      .then(({ counts: decoded }) => {
        // The contract's counts, once read, are the reference.
        if (!cancelled) setCounts((prev) => prev ?? decoded)
      })
      .catch((err) => {
        if (!cancelled) setError(`Could not decode the output: ${formatError(err)}`)
      })
    return () => {
      cancelled = true
    }
  }, [output])

  const refresh = useCallback(() => {
    const read = { address: e3Program, abi: SealedCcaProgram__factory.abi } as const
    publicClient
      .readContract({ ...read, functionName: 'clearing', args: [e3Id] })
      .then(async ([cleared, kind, step, pStar, fullTokens, marginalTokens, soldTotal, claimDeadline]) => {
        if (!cleared) return setClearing(null)
        setClearing({ kind: KINDS[kind], step, pStar, fullTokens, marginalTokens, soldTotal, claimDeadline })
        // The contract keeps no demand curve in storage: `SaleCleared` carries it. Read it once.
        if (countsFromEvent.current) return
        countsFromEvent.current = true
        const { logs } = await scanLogs((range) =>
          publicClient.getContractEvents({ ...read, eventName: 'SaleCleared', args: { e3Id }, strict: true, ...range }),
        )
        const last = logs.at(-1)
        if (last) setCounts([...last.args.c])
        else countsFromEvent.current = false
      })
      .catch((err) => {
        countsFromEvent.current = false
        console.warn('Could not read the clearing:', err)
      })
  }, [e3Program, e3Id])

  useEffect(() => {
    setClearing(null)
    countsFromEvent.current = false
    if (output === null) return
    refresh()
    const timer = setInterval(refresh, POLL_MS)
    return () => clearInterval(timer)
  }, [output, refresh])

  const clear = useCallback(async () => {
    if (!walletClient) return
    setBusy(true)
    setError(null)
    try {
      const [account] = await walletClient.getAddresses()
      const { request } = await publicClient.simulateContract({
        address: e3Program,
        abi: SealedCcaProgram__factory.abi,
        functionName: 'clear',
        args: [e3Id],
        account,
      })
      const receipt = await publicClient.waitForTransactionReceipt({ hash: await walletClient.writeContract(request) })
      if (receipt.status !== 'success') throw new Error('The clear transaction reverted')
      refresh()
    } catch (err) {
      setError(formatError(err))
    } finally {
      setBusy(false)
    }
  }, [walletClient, e3Program, e3Id, refresh])

  return { counts, clearing, clear, clearBusy: busy, error, refresh }
}
