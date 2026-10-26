// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useState } from 'react'
import { type Address, isAddress, zeroAddress } from 'viem'
import { generatePrivateKey, privateKeyToAddress } from 'viem/accounts'
import { downloadText } from '@/utils/bid-storage'

/** The address that receives the claim, and its private key when the app generated it. */
export interface Recipient {
  address: Address
  privateKey: `0x${string}` | null
}

interface Props {
  value: Recipient | null
  onChange: (value: Recipient | null) => void
  disabled: boolean
  /** Addresses that link to the bid: the recipient must not be one of them. */
  linked: readonly (Address | undefined)[]
}

/** Why `text` is no good recipient, or `null` when it is one. */
function recipientError(text: string, linked: Props['linked']): string | null {
  if (text === '') return null
  if (!isAddress(text)) return 'This is not an address.'
  if (text.toLowerCase() === zeroAddress) return 'The zero address cannot receive a claim.'
  if (linked.some((address) => address?.toLowerCase() === text.toLowerCase())) {
    return 'This address links to your bid. Use a fresh address.'
  }
  return null
}

/**
 * The recipient of a claim. The best choice is a fresh key pair that this page makes in the browser: the
 * address has no history, so nothing links it to the bid. The private key is shown once with a warning and
 * kept in this browser with the claim record.
 */
const RecipientPicker: React.FC<Props> = ({ value, onChange, disabled, linked }) => {
  const [mode, setMode] = useState<'generate' | 'custom'>('generate')
  const [custom, setCustom] = useState('')
  const [showKey, setShowKey] = useState(false)
  const error = recipientError(custom, linked)

  const generate = () => {
    const privateKey = generatePrivateKey()
    setShowKey(false)
    onChange({ address: privateKeyToAddress(privateKey), privateKey })
  }

  const selectMode = (next: 'generate' | 'custom') => {
    setMode(next)
    onChange(null)
    setCustom('')
  }

  return (
    <div className='space-y-3'>
      <p className='label !mb-0'>Recipient address</p>
      <div className='grid grid-cols-2 gap-2' role='radiogroup' aria-label='How to pick the recipient'>
        {(['generate', 'custom'] as const).map((option) => (
          <button
            key={option}
            type='button'
            role='radio'
            aria-checked={mode === option}
            disabled={disabled}
            onClick={() => selectMode(option)}
            className={`border px-3 py-2 text-sm transition-colors disabled:cursor-not-allowed ${
              mode === option ? 'border-ink bg-ink text-paper' : 'border-rule-strong bg-card hover:border-ink'
            }`}
          >
            {option === 'generate' ? 'Make a fresh address' : 'Use an address I have'}
          </button>
        ))}
      </div>

      {mode === 'generate' ? (
        <div className='space-y-3'>
          <button type='button' onClick={generate} disabled={disabled} className='btn sm'>
            {value ? 'Make another address' : 'Make a fresh address'}
          </button>
          {value?.privateKey && (
            <div className='space-y-3 border border-rule-strong bg-card p-4'>
              <p className='mono-sm muted'>Fresh address</p>
              <p className='addr break-all text-sm'>{value.address}</p>
              <div className='note warn space-y-2 text-xs'>
                <p>
                  <strong>Save the private key.</strong> It controls the tokens and the refund. This page cannot restore it. Anyone who has
                  it can take the funds. The address needs a little gas before you can move the tokens.
                </p>
                {showKey ? (
                  <p className='addr break-all'>{value.privateKey}</p>
                ) : (
                  <button type='button' onClick={() => setShowKey(true)} className='btn ghost sm'>
                    Show the private key
                  </button>
                )}
                <button
                  type='button'
                  onClick={() =>
                    downloadText(
                      `token-launch-recipient-${value.address}.json`,
                      JSON.stringify({ address: value.address, privateKey: value.privateKey }, null, 2),
                    )
                  }
                  className='btn ghost sm'
                >
                  Download the key file
                </button>
              </div>
            </div>
          )}
        </div>
      ) : (
        <div className='space-y-2'>
          <input
            aria-label='Recipient address'
            value={custom}
            disabled={disabled}
            spellCheck={false}
            placeholder='0x…'
            onChange={(event) => {
              const text = event.target.value.trim()
              setCustom(text)
              onChange(text !== '' && recipientError(text, linked) === null ? { address: text as Address, privateKey: null } : null)
            }}
            className='field font-mono text-xs'
          />
          <p className={`text-xs ${error ? 'text-danger' : 'text-ink-soft'}`}>
            {error ?? 'Use an address that never touched this bid, this wallet or its funds. Otherwise the claim is linkable.'}
          </p>
        </div>
      )}
    </div>
  )
}

export default RecipientPicker
