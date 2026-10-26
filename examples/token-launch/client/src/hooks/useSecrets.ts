// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useCallback, useEffect, useMemo, useState } from 'react'
import { type BidSecret, downloadText, exportBackup, importBackup, loadSecrets } from '@/utils/bid-storage'
import { chain } from '@/utils/chain'
import { getContractAddresses } from '@/utils/env-config'
import type { LoggedBid } from './useBidLog'

/** A secret of this browser, and whether the chain holds the bid it opens. */
export interface HeldSecret {
  secret: BidSecret
  /** The bid with this index and commitment is on chain. A secret that is not confirmed may belong to a failed attempt. */
  confirmed: boolean
}

export interface UseSecrets {
  held: HeldSecret[]
  /** Read the browser storage again, after a bid or an import. */
  reload: () => void
  /** Offer the secrets of this sale as a file. */
  exportFile: () => void
  /** Read a backup file. Resolves to the number of secrets stored; rejects with a message when the file is wrong. */
  importFile: (file: File) => Promise<number>
}

/** The bid secrets of this browser for one sale, checked against the bids on chain. */
export function useSecrets(saleId: bigint, bids: readonly LoggedBid[] | null): UseSecrets {
  const { e3Program } = getContractAddresses()
  const key = useMemo(() => ({ chainId: chain.id, program: e3Program, saleId }), [e3Program, saleId])
  const [secrets, setSecrets] = useState<BidSecret[]>([])

  const reload = useCallback(() => setSecrets(loadSecrets(key)), [key])
  useEffect(reload, [reload])

  const held = useMemo(
    () =>
      secrets.map((secret): HeldSecret => {
        const logged = bids?.find((bid) => bid.index === secret.index)
        return { secret, confirmed: logged?.bidCommitment.toLowerCase() === secret.bidCommitment.toLowerCase() }
      }),
    [secrets, bids],
  )

  const exportFile = useCallback(() => {
    downloadText(`token-launch-bid-secret-sale-${saleId}.json`, exportBackup(key, loadSecrets(key)))
  }, [key, saleId])

  const importFile = useCallback(
    async (file: File) => {
      const stored = importBackup(await file.text(), { chainId: key.chainId, program: key.program })
      reload()
      return stored
    },
    [key, reload],
  )

  return { held, reload, exportFile, importFile }
}
