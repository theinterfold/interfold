// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useEffect, useState } from 'react'
import { isAddress } from 'viem'
import { type TokenInfo, readTokenInfo } from '@/utils/tokens'

export type TokenLookup =
  | { status: 'empty' }
  | { status: 'invalid' }
  | { status: 'loading' }
  | { status: 'missing' }
  | { status: 'ok'; token: TokenInfo }

/** The symbol and decimals of the ERC-20 at the address that the user typed. */
export function useTokenInfo(text: string): TokenLookup {
  const [lookup, setLookup] = useState<TokenLookup>({ status: 'empty' })

  useEffect(() => {
    const trimmed = text.trim()
    if (trimmed === '') return setLookup({ status: 'empty' })
    if (!isAddress(trimmed)) return setLookup({ status: 'invalid' })
    let cancelled = false
    setLookup({ status: 'loading' })
    readTokenInfo(trimmed)
      .then((token) => {
        if (!cancelled) setLookup({ status: 'ok', token })
      })
      .catch(() => {
        if (!cancelled) setLookup({ status: 'missing' })
      })
    return () => {
      cancelled = true
    }
  }, [text])

  return lookup
}

/** A line under a token address field: what the lookup found. */
export function lookupNote(lookup: TokenLookup): string {
  switch (lookup.status) {
    case 'empty':
      return 'The address of an ERC-20 token.'
    case 'invalid':
      return 'This is not an address.'
    case 'loading':
      return 'Reading the token…'
    case 'missing':
      return 'No ERC-20 token found at this address on this network.'
    case 'ok':
      return `${lookup.token.symbol}, ${lookup.token.decimals} decimals.`
  }
}
