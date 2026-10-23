// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { formatUnits } from 'viem'
import {
  AUCTION_TYPES,
  AUCTION_TYPE_DESCRIPTIONS,
  AUCTION_TYPE_LABELS,
  AuctionType,
  LEVELS,
  MAX_BIDDERS_BY_TYPE,
  MIN_BIDDERS,
  isRatioType,
  rolesFor,
} from '@shared/layout'
import { STEP_LABELS, useCreateAuction } from '@/hooks/useCreateAuction'
import { useWallet } from '@/hooks/useWallet'
import { chain } from '@/utils/chain'
import { ConnectPrompt } from '@/components/ConnectPrompt'
import { INITIAL_PRICE_FORM, PriceLevelsField, pricesOf } from '@/components/PriceLevelsField'
import Spinner from '@/components/Spinner'

/** The contract rejects titles outside 1..80 bytes of UTF-8. */
const MAX_TITLE_BYTES = 80

const DURATIONS = [
  { label: '15 minutes', seconds: 15 * 60 },
  { label: '30 minutes', seconds: 30 * 60 },
  { label: '1 hour', seconds: 60 * 60 },
  { label: '2 hours', seconds: 2 * 60 * 60 },
] as const

const NEXT_STEPS = [
  'You approve the fee token and send the request. The wallet asks you to sign each.',
  'The committee of ciphernodes generates the key. This takes several minutes.',
  'Bidding opens once the key is published and stays open until the duration ends.',
  'After the window closes the result is computed and decrypted. Share the auction link with the bidders.',
]

const titleBytes = (title: string) => new TextEncoder().encode(title).length

const CreateAuction: React.FC = () => {
  const navigate = useNavigate()
  const { address, wrongChain, ready } = useWallet()
  const create = useCreateAuction(address)

  const [title, setTitle] = useState('')
  const [auctionType, setAuctionType] = useState<AuctionType>(AuctionType.SecondPrice)
  const [priceForm, setPriceForm] = useState(INITIAL_PRICE_FORM)
  const [durationSeconds, setDurationSeconds] = useState<number>(DURATIONS[2].seconds)

  const trimmed = title.trim()
  const bytes = titleBytes(trimmed)
  const titleValid = bytes > 0 && bytes <= MAX_TITLE_BYTES
  const priced = pricesOf(priceForm)
  const busy = create.step !== 'idle'
  const canSubmit = ready && titleValid && 'prices' in priced && !busy && create.shortfall === null

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    if (!canSubmit || !('prices' in priced)) return
    const e3Id = await create.create({ title: trimmed, auctionType, prices: priced.prices, durationSeconds })
    if (e3Id !== null) navigate(`/auction/${e3Id}`)
  }

  const fee = (amount: bigint) => `${formatUnits(amount, create.feeToken?.decimals ?? 6)} ${create.feeToken?.symbol ?? ''}`.trim()

  return (
    <div className='page'>
      <header className='mb-10 max-w-3xl space-y-4'>
        <p className='mono muted'>New auction</p>
        <h1 className='h1'>Create an auction</h1>
        <p className='lede'>
          Choose what the auction reveals, then request it. Each bidder bids one of {LEVELS} price levels. Each type has its own limit on
          the number of bidders.
        </p>
      </header>

      <div className='grid items-start gap-10 lg:grid-cols-[1.4fr_1fr]'>
        <form onSubmit={(event) => void submit(event)} className='card space-y-7 !p-5 md:!p-8'>
          <div>
            <label htmlFor='title' className='label'>
              Title
            </label>
            <input
              id='title'
              value={title}
              onChange={(event) => setTitle(event.target.value)}
              disabled={busy}
              placeholder='What is being auctioned'
              className='field'
            />
            <p className={`mt-1 text-xs ${bytes > MAX_TITLE_BYTES ? 'text-danger' : 'text-ink-soft'}`}>
              {bytes}/{MAX_TITLE_BYTES} bytes
            </p>
          </div>

          <fieldset className='space-y-3' disabled={busy}>
            <legend className='label'>Auction type</legend>
            {AUCTION_TYPES.map((type) => (
              <label key={type} className={`choice ${auctionType === type ? 'on' : ''}`}>
                <input type='radio' name='auction-type' checked={auctionType === type} onChange={() => setAuctionType(type)} />
                <span className='space-y-1'>
                  <span className='block font-semibold'>{AUCTION_TYPE_LABELS[type]}</span>
                  <span className='block text-sm text-ink-soft'>{AUCTION_TYPE_DESCRIPTIONS[type]}</span>
                  <span className='block font-mono text-xs text-ink-soft'>{rolesFor(type).length} ciphertexts for each bid</span>
                </span>
              </label>
            ))}
            <p className='text-sm text-ink-soft' aria-live='polite'>
              This type takes {MIN_BIDDERS} to <strong>{MAX_BIDDERS_BY_TYPE[auctionType]}</strong> bidders.
              {isRatioType(auctionType)
                ? ` Ratio-lane types allow more bidders than the other types (${MAX_BIDDERS_BY_TYPE[AuctionType.FirstPrice]} for them). If the top bids tie, a public random draw picks the winner among the tied bidders. The tie becomes public: the result names every bidder that tied.`
                : ' If the top bids tie, a priority taken from a hash of the published ciphertexts picks the winner. Nothing about the tie is revealed.'}
            </p>
          </fieldset>

          <PriceLevelsField form={priceForm} onChange={setPriceForm} disabled={busy} />

          <div>
            <label htmlFor='duration' className='label'>
              Bidding duration
            </label>
            <select
              id='duration'
              value={durationSeconds}
              onChange={(event) => setDurationSeconds(Number(event.target.value))}
              disabled={busy}
              className='field'
            >
              {DURATIONS.map(({ label, seconds }) => (
                <option key={seconds} value={seconds}>
                  {label}
                </option>
              ))}
            </select>
            <p className='mt-1 text-xs text-ink-soft'>
              The duration counts from the request. Key generation takes several minutes and bids open only once the key is published, so
              bidding gets less than the full time. Proving a bid takes several minutes too: leave room for it.
            </p>
          </div>

          {!ready && !wrongChain && <ConnectPrompt>Connect a wallet to create an auction.</ConnectPrompt>}
          {wrongChain && <div className='note bad'>Your wallet is on another network. Switch to {chain.name} to continue.</div>}

          {create.shortfall && (
            <div className='note warn space-y-3'>
              <p>
                The E3 fee is <strong>{fee(create.shortfall.needed)}</strong> and this account holds{' '}
                <strong>{fee(create.shortfall.balance)}</strong>.
              </p>
              {create.tokenSource ? (
                <>
                  <button type='button' onClick={() => void create.getTestTokens()} disabled={busy} className='btn sm'>
                    {busy ? 'Working…' : create.tokenSource === 'faucet' ? 'Get test tokens' : 'Mint test fee tokens'}
                  </button>
                  {create.tokenSource === 'faucet' && (
                    <p className='text-xs'>The faucet sends test tokens to accounts that hold little. You also need test ETH for gas.</p>
                  )}
                </>
              ) : (
                <p>Add fee tokens to this account, then try again.</p>
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
              'Create auction'
            )}
          </button>
          <p className='text-center text-xs text-ink-soft'>
            Creating an auction pays the E3 fee in the fee token{create.feeToken ? ` (${create.feeToken.symbol})` : ''}. Bidders pay only
            gas.
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

export default CreateAuction
