// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useState } from 'react'
import { isAddress, type Address } from 'viem'
import { type AuctionType, MAX_PROVIDERS, providersError } from '@interfold/auction-core'
import { hasProviders } from '@/utils/designs'

/**
 * The providers that the rows of the editor name, and the reason they are not valid, if they are not.
 * Types without providers give an empty list and no error.
 */
export function checkProviders(type: AuctionType, rows: readonly string[]): { providers: Address[]; error: string | null } {
  if (!hasProviders(type)) return { providers: [], error: null }
  const typed = rows.map((row) => row.trim())
  if (typed.some((row) => row === '')) return { providers: [], error: 'Fill in or remove the empty row.' }
  const wrong = typed.find((row) => !isAddress(row))
  if (wrong !== undefined) return { providers: [], error: `Not an address: ${wrong}` }
  const providers = typed as Address[]
  return { providers, error: providersError(type, providers) }
}

interface ProvidersFieldProps {
  rows: string[]
  onChange: (rows: string[]) => void
  disabled?: boolean
  error: string | null
  /** The connected wallet, offered as a provider. */
  account: Address | undefined
  /** The mask provider of the server: `undefined` while it loads, `null` when the server has none. */
  serverProvider: Address | null | undefined
}

const includes = (rows: readonly string[], address: string) => rows.some((row) => row.trim().toLowerCase() === address.toLowerCase())

/** The editor of the mask providers of a mask-provider auction: 1 to `MAX_PROVIDERS` addresses. */
export const ProvidersField: React.FC<ProvidersFieldProps> = ({ rows, onChange, disabled, error, account, serverProvider }) => {
  const full = rows.length >= MAX_PROVIDERS
  // A stable key for each row, so that removing a row in the middle keeps the focus on the right input.
  // The rows come from the parent. When their number differs from the keys, the parent has replaced them: number them again.
  const [ids, setIds] = useState<number[]>([])
  const keys = ids.length === rows.length ? ids : rows.map((_, index) => index)
  const add = (address: string) => {
    setIds([...keys, Math.max(-1, ...keys) + 1])
    onChange([...rows, address])
  }
  const remove = (index: number) => {
    setIds(keys.filter((_, i) => i !== index))
    onChange(rows.filter((_, i) => i !== index))
  }
  return (
    <fieldset className='space-y-3' disabled={disabled}>
      <legend className='label'>Mask providers</legend>
      <p className='text-sm text-muted'>
        A mask provider hides the losing bids. Each provider sends one random mask before bidding opens. Privacy needs one honest provider
        that keeps its mask secret. The auction needs every provider to send its mask, and bidding stays closed until all of them have. Name
        1 to {MAX_PROVIDERS} addresses.
      </p>
      <ul className='space-y-2'>
        {rows.map((row, index) => (
          <li key={keys[index]} className='flex items-center gap-2'>
            <input
              value={row}
              aria-invalid={row.trim() !== '' && !isAddress(row.trim())}
              onChange={(event) => onChange(rows.map((current, i) => (i === index ? event.target.value : current)))}
              spellCheck={false}
              placeholder='0x…'
              aria-label={`Mask provider ${index + 1}`}
              className={`field font-mono text-xs ${row.trim() !== '' && !isAddress(row.trim()) ? '!border-negative' : ''}`}
            />
            <button type='button' className='btn ghost sm' onClick={() => remove(index)}>
              Remove
            </button>
          </li>
        ))}
      </ul>
      <div className='flex flex-wrap gap-2'>
        <button type='button' className='btn ghost sm' disabled={full} onClick={() => add('')}>
          Add a provider
        </button>
        {account && !includes(rows, account) && (
          <button type='button' className='btn ghost sm' disabled={full} onClick={() => add(account)}>
            Add my wallet
          </button>
        )}
        {serverProvider && !includes(rows, serverProvider) && (
          <button type='button' className='btn ghost sm' disabled={full} onClick={() => add(serverProvider)}>
            Add the server provider
          </button>
        )}
      </div>
      {serverProvider && (
        <p className='text-xs text-muted'>The demo server can be a provider. If you add it, the server sends its own mask.</p>
      )}
      <p className={`text-xs ${error ? 'text-negative' : 'text-muted'}`} role={error ? 'alert' : undefined}>
        {error ?? `${rows.length} of at most ${MAX_PROVIDERS} providers. A provider cannot bid in this auction.`}
      </p>
      {serverProvider === null && (
        <p className='text-xs text-muted'>
          This deployment has no server provider, so a provider you name must send its mask itself, from this page.
        </p>
      )}
    </fieldset>
  )
}
