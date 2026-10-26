// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useState } from 'react'
import { Link } from 'react-router-dom'
import { isAddress } from 'viem'
import { LEVELS, MIN_LEVELS, gridFor, priceAt } from '@interfold/negotiation'
import { STEP_LABELS, useCreateNegotiation } from '@/hooks/useCreateNegotiation'
import { useWallet } from '@/hooks/useWallet'
import { chain } from '@/utils/chain'
import { joinTitle } from '@/utils/negotiation'
import { formatAmount } from '@/utils/tokens'
import { ConnectPrompt } from '@/components/ConnectPrompt'
import Spinner from '@/components/Spinner'

/** The title and its unit label share one string on chain, so the UI limits the whole string. */
const MAX_TITLE_BYTES = 80
const MAX_UNIT_LENGTH = 12
/** The contract takes every price term below 2^128. */
const PRICE_LIMIT = 2n ** 128n
const MIN_MINUTES = 5
const MAX_MINUTES = 24 * 60

const NEXT_STEPS = [
  'You approve the fee token, then send the request. The wallet asks you to sign each.',
  'The committee of ciphernodes generates the key. This takes several minutes.',
  'You send the link to the seller and the buyer. Each connects its own wallet and seals one price in its browser.',
  'After the window closes the program combines the two sealed prices. The committee decrypts only the result.',
  'Anyone settles the result on chain. Both parties learn the agreed price, or that there is no match.',
]

const titleBytes = (title: string) => new TextEncoder().encode(title).length

/** A whole number typed in a field, or `null`. */
function parsePrice(text: string): bigint | null {
  if (!/^\d+$/.test(text)) return null
  const value = BigInt(text)
  return value < PRICE_LIMIT ? value : null
}

const CreateNegotiation: React.FC = () => {
  const { address, wrongChain, ready } = useWallet()
  const create = useCreateNegotiation(address)

  const [title, setTitle] = useState('')
  const [unit, setUnit] = useState('')
  const [sellerText, setSellerText] = useState('')
  const [buyerText, setBuyerText] = useState('')
  const [minText, setMinText] = useState('100')
  const [maxText, setMaxText] = useState('250')
  const [stepText, setStepText] = useState('10')
  const [minutesText, setMinutesText] = useState('30')
  const [createdId, setCreatedId] = useState<bigint | null>(null)
  const [copied, setCopied] = useState(false)

  const trimmedTitle = title.trim()
  const trimmedUnit = unit.trim()
  const stored = joinTitle(trimmedTitle, trimmedUnit)
  const bytes = titleBytes(stored)
  const titleValid = trimmedTitle.length > 0 && bytes <= MAX_TITLE_BYTES
  const unitValid = !/[[\]]/.test(trimmedUnit)

  const seller = sellerText.trim()
  const buyer = buyerText.trim()
  const sellerValid = isAddress(seller)
  const buyerValid = isAddress(buyer)
  const sameParty = sellerValid && buyerValid && seller.toLowerCase() === buyer.toLowerCase()

  const min = parsePrice(minText)
  const max = parsePrice(maxText)
  const stepSize = parsePrice(stepText)
  const grid =
    min !== null && max !== null && stepSize !== null ? gridFor(min, max, stepSize) : { error: 'the prices are whole numbers below 2^128' }
  const levels = 'levels' in grid ? grid.levels : null

  const minutes = /^\d+$/.test(minutesText) ? Number(minutesText) : null
  const minutesValid = minutes !== null && minutes >= MIN_MINUTES && minutes <= MAX_MINUTES

  const busy = create.step !== 'idle'
  const canSubmit =
    ready &&
    titleValid &&
    unitValid &&
    sellerValid &&
    buyerValid &&
    !sameParty &&
    levels !== null &&
    min !== null &&
    stepSize !== null &&
    minutesValid &&
    !busy &&
    create.shortfall === null

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    if (!canSubmit || levels === null || min === null || stepSize === null || minutes === null) return
    const e3Id = await create.create({
      title: stored,
      seller: seller as `0x${string}`,
      buyer: buyer as `0x${string}`,
      levels,
      minPrice: min,
      stepPrice: stepSize,
      durationSeconds: minutes * 60,
    })
    if (e3Id !== null) setCreatedId(e3Id)
  }

  const link = createdId === null ? null : `${window.location.origin}/n/${createdId}`

  if (createdId !== null && link !== null) {
    return (
      <div className='page'>
        <div className='card max-w-3xl space-y-6 !p-5 md:!p-8'>
          <p className='mono muted'>Nº {createdId.toString().padStart(3, '0')}</p>
          <h1 className='h1'>The negotiation is created</h1>
          <p className='lede'>
            Send this link to the seller and to the buyer. Each connects its own wallet and seals one price. The offers open once the
            committee has generated its key, which takes several minutes.
          </p>
          <div className='note space-y-3'>
            <p className='mono-sm muted'>Link to share</p>
            <p className='addr break-all'>{link}</p>
            <button
              type='button'
              className='btn sm'
              onClick={() => {
                void navigator.clipboard.writeText(link).then(() => {
                  setCopied(true)
                  setTimeout(() => setCopied(false), 2000)
                })
              }}
            >
              {copied ? 'Link copied' : 'Copy link'}
            </button>
          </div>
          <Link to={`/n/${createdId}`} className='btn accent lg block'>
            Open the negotiation
          </Link>
        </div>
      </div>
    )
  }

  const shortfall = create.shortfall
  const fee = (value: bigint, token: { symbol: string; decimals: number }) =>
    `${formatAmount(value, token.decimals)} ${token.symbol}`.trim()
  const fieldNote = (invalid: boolean, text: string, fallback: string) => (
    <p className={`mt-1 text-xs ${invalid ? 'text-danger' : 'text-ink-soft'}`}>{invalid ? text : fallback}</p>
  )

  return (
    <div className='page'>
      <header className='mb-10 max-w-3xl space-y-4'>
        <p className='mono muted'>New negotiation</p>
        <h1 className='h1'>Create a sealed negotiation</h1>
        <p className='lede'>
          A seller and a buyer each seal one price. If the buyer&rsquo;s maximum is at least the seller&rsquo;s minimum, both learn one
          agreed price. Otherwise both learn only that there is no match. Neither price is ever revealed.
        </p>
      </header>

      <div className='grid items-start gap-10 lg:grid-cols-[1.4fr_1fr]'>
        <form onSubmit={(event) => void submit(event)} className='card space-y-7 !p-5 md:!p-8'>
          <fieldset className='space-y-5' disabled={busy}>
            <legend className='label'>What is negotiated</legend>
            <div>
              <label htmlFor='title' className='label'>
                Title
              </label>
              <input
                id='title'
                value={title}
                onChange={(event) => setTitle(event.target.value)}
                placeholder='What the parties negotiate'
                className='field'
              />
              {fieldNote(
                bytes > MAX_TITLE_BYTES,
                `The title and the unit take at most ${MAX_TITLE_BYTES} bytes.`,
                `${bytes}/${MAX_TITLE_BYTES} bytes, with the unit.`,
              )}
            </div>
            <div>
              <label htmlFor='unit' className='label'>
                Unit label (optional)
              </label>
              <input
                id='unit'
                value={unit}
                maxLength={MAX_UNIT_LENGTH}
                onChange={(event) => setUnit(event.target.value)}
                placeholder='EUR, USD, kg …'
                className='field'
              />
              {fieldNote(
                !unitValid,
                'The unit label has no square brackets.',
                'Shown next to every price. Prices are plain numbers: no token moves.',
              )}
            </div>
          </fieldset>

          <fieldset className='space-y-5' disabled={busy}>
            <legend className='label'>The two parties</legend>
            <div>
              <label htmlFor='seller' className='label'>
                Seller address
              </label>
              <div className='flex gap-2'>
                <input
                  id='seller'
                  value={sellerText}
                  onChange={(event) => setSellerText(event.target.value)}
                  spellCheck={false}
                  placeholder='0x…'
                  className='field font-mono text-xs'
                />
                {address && (
                  <button type='button' onClick={() => setSellerText(address)} className='btn ghost sm shrink-0'>
                    Me
                  </button>
                )}
              </div>
              {fieldNote(sellerText !== '' && !sellerValid, 'This is not an address.', 'The seller sends a minimum price.')}
            </div>
            <div>
              <label htmlFor='buyer' className='label'>
                Buyer address
              </label>
              <div className='flex gap-2'>
                <input
                  id='buyer'
                  value={buyerText}
                  onChange={(event) => setBuyerText(event.target.value)}
                  spellCheck={false}
                  placeholder='0x…'
                  className='field font-mono text-xs'
                />
                {address && (
                  <button type='button' onClick={() => setBuyerText(address)} className='btn ghost sm shrink-0'>
                    Me
                  </button>
                )}
              </div>
              {fieldNote(
                (buyerText !== '' && !buyerValid) || sameParty,
                sameParty ? 'The seller and the buyer are two different addresses.' : 'This is not an address.',
                'The buyer sends a maximum price.',
              )}
            </div>
          </fieldset>

          <fieldset className='space-y-5' disabled={busy}>
            <legend className='label'>Price range</legend>
            <div className='grid gap-4 sm:grid-cols-3'>
              <div>
                <label htmlFor='min' className='label'>
                  Minimum
                </label>
                <input
                  id='min'
                  inputMode='numeric'
                  value={minText}
                  onChange={(event) => setMinText(event.target.value.trim())}
                  className='field font-mono'
                />
              </div>
              <div>
                <label htmlFor='max' className='label'>
                  Maximum
                </label>
                <input
                  id='max'
                  inputMode='numeric'
                  value={maxText}
                  onChange={(event) => setMaxText(event.target.value.trim())}
                  className='field font-mono'
                />
              </div>
              <div>
                <label htmlFor='step' className='label'>
                  Step
                </label>
                <input
                  id='step'
                  inputMode='numeric'
                  value={stepText}
                  onChange={(event) => setStepText(event.target.value.trim())}
                  className='field font-mono'
                />
              </div>
            </div>
            {fieldNote(
              levels === null,
              `Not a valid range: ${'error' in grid ? grid.error : ''}.`,
              `The range has ${levels} price levels. Both parties choose one of them. A range has ${MIN_LEVELS} to ${LEVELS} levels.`,
            )}
            {levels !== null && min !== null && stepSize !== null && (
              <div className='flex flex-wrap gap-2' aria-label='Price levels'>
                {Array.from({ length: levels }, (_, level) => (
                  <span key={level} className='border border-rule-strong bg-card px-2 py-1 font-mono text-xs'>
                    {priceAt(min, stepSize, level).toLocaleString('en-US')}
                  </span>
                ))}
              </div>
            )}
          </fieldset>

          <div>
            <label htmlFor='minutes' className='label'>
              Offer window (minutes)
            </label>
            <input
              id='minutes'
              inputMode='numeric'
              value={minutesText}
              onChange={(event) => setMinutesText(event.target.value.trim())}
              disabled={busy}
              className='field font-mono'
            />
            {fieldNote(
              !minutesValid,
              `The window is ${MIN_MINUTES} to ${MAX_MINUTES} minutes.`,
              'The window counts from the request. Key generation takes several minutes and offers open only once the key is published. Each party then needs several minutes to encrypt and prove its price: leave room for it.',
            )}
          </div>

          {!ready && !wrongChain && <ConnectPrompt>Connect a wallet to create a negotiation.</ConnectPrompt>}
          {wrongChain && <div className='note bad'>Your wallet is on another network. Switch to {chain.name} to continue.</div>}

          {shortfall && (
            <div className='note warn space-y-3'>
              <p>
                The E3 fee is <strong>{fee(shortfall.needed, shortfall.token)}</strong> and this account holds{' '}
                <strong>{fee(shortfall.balance, shortfall.token)}</strong>.
              </p>
              {create.tokenSource ? (
                <>
                  <button type='button' onClick={() => void create.getTestTokens()} disabled={busy} className='btn sm'>
                    {busy ? 'Working…' : create.tokenSource === 'faucet' ? 'Get test tokens' : `Mint test ${shortfall.token.symbol}`}
                  </button>
                  {create.tokenSource === 'faucet' && (
                    <p className='text-xs'>The faucet sends test tokens to accounts that hold little. You also need test ETH for gas.</p>
                  )}
                </>
              ) : (
                <p>Add {shortfall.token.symbol} to this account, then try again.</p>
              )}
            </div>
          )}
          {create.error && <div className='note bad'>{create.error}</div>}

          <button type='submit' disabled={!canSubmit} className='btn accent lg block'>
            {busy ? (
              <>
                <Spinner size={14} /> {STEP_LABELS[create.step as Exclude<typeof create.step, 'idle'>]}
              </>
            ) : (
              'Create negotiation'
            )}
          </button>
          <p className='text-center text-xs text-ink-soft'>
            Creating a negotiation pays the E3 fee in the fee token. The parties pay only gas.
          </p>
        </form>

        <aside className='card flat space-y-5 lg:sticky lg:top-8'>
          <p className='mono muted'>What happens next</p>
          <ol className='steps'>
            {NEXT_STEPS.map((text, index) => (
              <li key={text} className='step'>
                <span className='pin'>{index + 1}</span>
                <p className='text-sm text-ink-2'>{text}</p>
              </li>
            ))}
          </ol>
        </aside>
      </div>
    </div>
  )
}

export default CreateNegotiation
