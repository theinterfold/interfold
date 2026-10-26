// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useCallback, useEffect, useState } from 'react'
import { useWalletClient } from 'wagmi'
import { Outcome, type RoundOutput, decodeOutput } from '@interfold/private-round'
import { PrivateRoundProgram__factory } from '@contract-types/factories/contracts/PrivateRoundProgram__factory'
import { chain, publicClient } from '@/utils/chain'
import { getContractAddresses } from '@/utils/env-config'
import { formatError } from '@/utils/error-formatting'
import type { SaleState } from '@/utils/sale'

const POLL_MS = 5_000

/** The clearing of a round as the contract stores it. It holds the outcome and the step, and nothing about the bids. */
export interface Clearing {
  outcome: Outcome
  /** `l*` when sold out, the reserve step when undersubscribed, 0 otherwise. */
  step: number
  /** The uniform price of one whole sale token, in payment-token base units. 0 when nothing sells. */
  pStar: bigint
  /** The number of counted bidders. */
  counted: number
  /** Unix seconds. Bidders above the clearing step claim up to `phase1End`. */
  phase1End: bigint
  /** Unix seconds. Bidders at the clearing step register after `phase1End` and up to `phase2End`. */
  phase2End: bigint
  /** Unix seconds: the last second at which `claim` works. After it the creator can sweep what is left. */
  claimDeadline: bigint
  /** The bidders above the clearing step that took their lot in phase 1. */
  aboveClaimed: number
  /** The bidders at the clearing step that registered in phase 2. */
  marginalRegistered: number
}

export interface UseClearing {
  /** What the published output says, as soon as the committee has decrypted it: the outcome, the step and `counted`. `null` until then. */
  preview: RoundOutput | null
  /** `null` until the round is cleared on chain. */
  clearing: Clearing | null
  clear: () => Promise<void>
  clearBusy: boolean
  error: string | null
  refresh: () => void
}

/** The clearing of a round whose output is published. Anyone can send the `clear` transaction. */
export function useClearing(sale: SaleState): UseClearing {
  const { data: walletClient } = useWalletClient({ chainId: chain.id })
  const { e3Program } = getContractAddresses()
  const [preview, setPreview] = useState<RoundOutput | null>(null)
  const [clearing, setClearing] = useState<Clearing | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const output = sale.plaintextOutput
  const e3Id = sale.e3Id
  const levels = sale.prices.length
  const { reserveStep, lots, minLots } = sale

  // The output decodes as soon as it is published: the page shows it before anyone clears the round.
  useEffect(() => {
    setPreview(null)
    if (output === null) return
    let cancelled = false
    decodeOutput(output, { levels, reserveStep, lots, minLots })
      .then((decoded) => {
        if (!cancelled) setPreview(decoded)
      })
      .catch((err) => {
        if (!cancelled) setError(`Could not decode the output: ${formatError(err)}`)
      })
    return () => {
      cancelled = true
    }
  }, [output, levels, reserveStep, lots, minLots])

  const refresh = useCallback(() => {
    publicClient
      .readContract({ address: e3Program, abi: PrivateRoundProgram__factory.abi, functionName: 'clearing', args: [e3Id] })
      .then(([cleared, outcome, step, pStar, counted, phase1End, phase2End, claimDeadline, aboveClaimed, marginalRegistered]) => {
        if (!cleared) return setClearing(null)
        setClearing({
          outcome: outcome as Outcome,
          step,
          pStar,
          counted: Number(counted),
          phase1End,
          phase2End,
          claimDeadline,
          aboveClaimed: Number(aboveClaimed),
          marginalRegistered: Number(marginalRegistered),
        })
      })
      .catch((err) => console.warn('Could not read the clearing:', err))
  }, [e3Program, e3Id])

  useEffect(() => {
    setClearing(null)
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
        abi: PrivateRoundProgram__factory.abi,
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

  return { preview, clearing, clear, clearBusy: busy, error, refresh }
}
