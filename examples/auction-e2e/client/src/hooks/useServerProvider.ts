// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useEffect, useState } from 'react'
import type { Address } from 'viem'
import { fetchServerProvider } from '@/utils/provider'

/** The mask provider address of the coordination server: `undefined` while it loads, `null` when the server has none. */
export function useServerProvider(): Address | null | undefined {
  const [address, setAddress] = useState<Address | null | undefined>(undefined)

  useEffect(() => {
    let cancelled = false
    void fetchServerProvider().then((found) => {
      if (!cancelled) setAddress(found)
    })
    return () => {
      cancelled = true
    }
  }, [])

  return address
}
