// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useEffect, useState } from 'react'
import { isAddressEqual, zeroAddress, type Address } from 'viem'
import { readAllowlist } from '@/utils/auction-events'
import { ALLOWLIST_GATE_ADDRESS } from '@/utils/env-config'
import { formatError } from '@/utils/error-formatting'

/** How an auction decides who may bid, as far as this app can tell. */
export type GateKind = 'open' | 'allowlist' | 'unknown'

export function gateKind(gate: Address): GateKind {
  if (gate === zeroAddress) return 'open'
  return ALLOWLIST_GATE_ADDRESS && isAddressEqual(gate, ALLOWLIST_GATE_ADDRESS) ? 'allowlist' : 'unknown'
}

export interface UseAllowlist {
  /** The members the creator listed, or `null` while they load (or when the gate is not an allowlist). */
  members: Address[] | null
  error: string | null
}

/** The members of the allowlist of an auction, read from the `AllowlistSet` event of its gate. */
export function useAllowlist(gate: Address | undefined, e3Id: bigint | null): UseAllowlist {
  const [state, setState] = useState<UseAllowlist>({ members: null, error: null })
  const listed = gate !== undefined && gateKind(gate) === 'allowlist'

  useEffect(() => {
    setState({ members: null, error: null })
    if (!listed || gate === undefined || e3Id === null) return
    let cancelled = false
    readAllowlist(gate, e3Id)
      .then((members) => {
        if (cancelled) return
        setState(members ? { members, error: null } : { members: null, error: 'The gate has no allowlist for this auction.' })
      })
      .catch((err) => {
        if (!cancelled) setState({ members: null, error: formatError(err) })
      })
    return () => {
      cancelled = true
    }
  }, [listed, gate, e3Id])

  return state
}
