// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useCallback, useState } from 'react'
import { useWalletClient } from 'wagmi'
import { negotiationProgramAbi } from '@interfold/negotiation'
import { chain, publicClient } from '@/utils/chain'
import { getContractAddresses } from '@/utils/env-config'
import { formatError } from '@/utils/error-formatting'

export interface UseSettle {
  settle: () => Promise<void>
  busy: boolean
  error: string | null
}

/** Anyone can send `settle(e3Id)` once the committee has published the output. `onSettled` runs after it is mined. */
export function useSettle(e3Id: bigint, account: `0x${string}` | undefined, onSettled: () => void): UseSettle {
  const { data: walletClient } = useWalletClient({ chainId: chain.id })
  const { e3Program } = getContractAddresses()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const settle = useCallback(async () => {
    if (!walletClient || !account) return
    setBusy(true)
    setError(null)
    try {
      const { request } = await publicClient.simulateContract({
        address: e3Program,
        abi: negotiationProgramAbi,
        functionName: 'settle',
        args: [e3Id],
        account,
      })
      const receipt = await publicClient.waitForTransactionReceipt({ hash: await walletClient.writeContract(request) })
      if (receipt.status !== 'success') throw new Error('The settle transaction reverted')
      onSettled()
    } catch (err) {
      setError(formatError(err))
    } finally {
      setBusy(false)
    }
  }, [walletClient, account, e3Program, e3Id, onSettled])

  return { settle, busy, error }
}
