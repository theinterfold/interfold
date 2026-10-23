// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { formatUnits, zeroAddress } from 'viem'
import {
  AUCTION_TYPES,
  AUCTION_TYPE_DESCRIPTIONS,
  AUCTION_TYPE_LABELS,
  AuctionType,
  MAX_BIDDERS_BY_TYPE,
  MIN_BIDDERS,
  isRatioType,
  rolesFor,
} from '@shared/layout'
import { MAX_ALLOWLIST_MEMBERS, encodeAllowlistConfig } from '@shared/allowlist'
import { STEP_LABELS, useCreateAuction } from '@/hooks/useCreateAuction'
import { useWallet } from '@/hooks/useWallet'
import { parseAllowlist } from '@/utils/allowlist-input'
import { chain } from '@/utils/chain'
import { ALLOWLIST_GATE_ADDRESS } from '@/utils/env-config'
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
  const [who, setWho] = useState<'anyone' | 'allowlist'>('anyone')
  const [allowlistText, setAllowlistText] = useState('')

  const trimmed = title.trim()
  const bytes = titleBytes(trimmed)
  const titleValid = bytes > 0 && bytes <= MAX_TITLE_BYTES
  const priced = pricesOf(priceForm)
  const busy = create.step !== 'idle'
  const listed = parseAllowlist(allowlistText)
  const listError =
    who !== 'allowlist'
      ? null
      : listed.invalid.length > 0
        ? `Not an address: ${listed.invalid[0]}${listed.invalid.length > 1 ? ` (and ${listed.invalid.length - 1} more)` : ''}`
        : listed.count === 0
          ? 'Add at least one address.'
          : listed.count > MAX_ALLOWLIST_MEMBERS
            ? `An allowlist has at most ${MAX_ALLOWLIST_MEMBERS} addresses, got ${listed.count}.`
            : null
  const canSubmit = ready && titleValid && 'prices' in priced && listError === null && !busy && create.shortfall === null

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    if (!canSubmit || !('prices' in priced)) return
    const gate = who === 'allowlist' ? ALLOWLIST_GATE_ADDRESS : undefined
    const e3Id = await create.create({
      title: trimmed,
      auctionType,
      prices: priced.prices,
      gate: gate ?? zeroAddress,
      gateConfig: gate ? encodeAllowlistConfig(listed.members) : '0x',
      durationSeconds,
    })
    if (e3Id !== null) navigate(`/auction/${e3Id}`)
  }

  const fee = (amount: bigint) => `${formatUnits(amount, create.feeToken?.decimals ?? 6)} ${create.feeToken?.symbol ?? ''}`.trim()

  return (
    <div className='page'>
      <header className='mb-10 max-w-3xl space-y-4'>
        <p className='mono muted'>New auction</p>
        <h1 className='h1'>Create an auction</h1>
        <p className='lede'>
          Choose what the auction reveals, how many price steps a bid can pick from, and the price of each step. Each type has its own limit
          on the number of bidders; the ratio types take the most.
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
                  <span className='block font-mono text-xs text-ink-soft'>
                    {MIN_BIDDERS} to {MAX_BIDDERS_BY_TYPE[type]} bidders · {rolesFor(type).length} ciphertexts for each bid
                  </span>
                </span>
              </label>
            ))}
            <p className='text-sm text-ink-soft' aria-live='polite'>
              {isRatioType(auctionType)
                ? `If the top bids tie, a public random draw picks the winner among the tied bidders. The tie becomes public: the result names every bidder that tied. This type takes up to ${MAX_BIDDERS_BY_TYPE[auctionType]} bidders, more than the ${MAX_BIDDERS_BY_TYPE[AuctionType.FirstPrice]} of the other types.`
                : `If the top bids tie, a priority taken from a hash of the published ciphertexts picks the winner. Nothing about the tie is revealed. This type takes up to ${MAX_BIDDERS_BY_TYPE[auctionType]} bidders.`}
            </p>
          </fieldset>

          <PriceLevelsField form={priceForm} onChange={setPriceForm} disabled={busy} />

          <fieldset className='space-y-3' disabled={busy}>
            <legend className='label'>Who can bid</legend>
            <label className={`choice ${who === 'anyone' ? 'on' : ''}`}>
              <input type='radio' name='who' checked={who === 'anyone'} onChange={() => setWho('anyone')} />
              <span className='space-y-1'>
                <span className='block font-semibold'>Anyone</span>
                <span className='block text-sm text-ink-soft'>Any address can bid, up to the limit of the auction type.</span>
              </span>
            </label>
            <label className={`choice ${who === 'allowlist' ? 'on' : ''} ${ALLOWLIST_GATE_ADDRESS ? '' : 'opacity-60'}`}>
              <input
                type='radio'
                name='who'
                checked={who === 'allowlist'}
                disabled={!ALLOWLIST_GATE_ADDRESS}
                onChange={() => setWho('allowlist')}
              />
              <span className='space-y-1'>
                <span className='block font-semibold'>Allowlist</span>
                <span className='block text-sm text-ink-soft'>
                  Only the addresses you list can bid. The list is public on chain, and the contract checks a Merkle proof of each bid.
                </span>
                {!ALLOWLIST_GATE_ADDRESS && (
                  <span className='block font-mono text-xs text-ink-soft'>Not available: this deployment has no allowlist gate.</span>
                )}
              </span>
            </label>
            {who === 'allowlist' && (
              <div>
                <label htmlFor='allowlist' className='label'>
                  Addresses
                </label>
                <textarea
                  id='allowlist'
                  value={allowlistText}
                  onChange={(event) => setAllowlistText(event.target.value)}
                  rows={5}
                  spellCheck={false}
                  placeholder='One address per line, or separated by commas'
                  className='field font-mono text-xs'
                />
                <p className={`mt-1 text-xs ${listError && allowlistText.trim() !== '' ? 'text-danger' : 'text-ink-soft'}`}>
                  {listError && allowlistText.trim() !== ''
                    ? listError
                    : `${listed.count} unique ${listed.count === 1 ? 'address' : 'addresses'} (at most ${MAX_ALLOWLIST_MEMBERS}). Sorted and deduplicated before they are sent.`}
                </p>
              </div>
            )}
          </fieldset>

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
