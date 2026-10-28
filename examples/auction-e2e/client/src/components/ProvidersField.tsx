// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { isAddress, type Address } from 'viem'
import { type AuctionType, MAX_PROVIDERS, isProviderType, providersError } from '@interfold/auction'

/**
 * The providers that the rows of the editor name, and the reason they are not valid, if they are not.
 * Types without providers give an empty list and no error.
 */
export function checkProviders(type: AuctionType, rows: readonly string[]): { providers: Address[]; error: string | null } {
  if (!isProviderType(type)) return { providers: [], error: null }
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

/** The editor of the mask providers of a type-4 auction: 1 to `MAX_PROVIDERS` addresses. */
export const ProvidersField: React.FC<ProvidersFieldProps> = ({ rows, onChange, disabled, error, account, serverProvider }) => {
  const full = rows.length >= MAX_PROVIDERS
  const add = (address: string) => onChange([...rows, address])
  return (
    <fieldset className='space-y-3' disabled={disabled}>
      <legend className='label'>Mask providers</legend>
      <p className='text-sm text-muted'>
        Each provider sends one random mask before bidding opens. Privacy needs one honest provider that keeps its mask secret, and the
        auction needs every provider to send its mask: bidding stays closed until all of them have. Name 1 to {MAX_PROVIDERS} addresses.
      </p>
      <ul className='space-y-2'>
        {rows.map((row, index) => (
          <li key={index} className='flex items-center gap-2'>
            <input
              value={row}
              onChange={(event) => onChange(rows.map((current, i) => (i === index ? event.target.value : current)))}
              spellCheck={false}
              placeholder='0x…'
              aria-label={`Mask provider ${index + 1}`}
              className='field font-mono text-xs'
            />
            <button type='button' className='btn ghost sm' onClick={() => onChange(rows.filter((_, i) => i !== index))}>
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
      <p className={`text-xs ${error ? 'text-negative' : 'text-muted'}`}>
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
