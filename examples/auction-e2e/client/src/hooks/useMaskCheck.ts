// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useEffect, useState } from 'react'
import type { Address } from 'viem'
import { checkMasks } from '@interfold/auction'
import { readSubmittedMasks } from '@/utils/auction-events'
import { opensCommitment } from '@/utils/commitments'

/**
 * The mask providers whose mask on chain does not open its commitment. The contract cannot check
 * this: the program does, and it stops without a valid mask from every provider. The hook reads the
 * `MaskSubmitted` events again each time the number of masks changes.
 *
 * @param providers The providers of the auction, in the order the creator named them.
 * @param submitted How many of them have sent a mask.
 */
export function useInvalidMasks(e3Id: bigint, providers: readonly Address[], submitted: number): Address[] {
  // The result remembers what it was computed for, so a stale one is never shown for another auction or mask count.
  const [found, setFound] = useState<{ query: string; invalid: Address[] }>({ query: '', invalid: [] })
  const query = `${e3Id}:${providers.join(',')}:${submitted}`

  useEffect(() => {
    if (submitted === 0) return
    let cancelled = false
    readSubmittedMasks(e3Id)
      .then(async (masks) => {
        const opens = await opensCommitment(masks.map((mask) => mask.ciphertext))
        if (!cancelled) setFound({ query, invalid: checkMasks(masks, providers, opens).invalid })
      })
      .catch((err) => console.warn('Could not check the masks:', err))
    return () => {
      cancelled = true
    }
    // `query` stands for the auction, its providers and the mask count.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query])

  return found.query === query ? found.invalid : []
}
