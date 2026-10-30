// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useWalletClient } from 'wagmi'
import { formatUnits, zeroAddress } from 'viem'
import {
  AUCTION_TYPES,
  AuctionType,
  MAX_ALLOWLIST_MEMBERS,
  MAX_BIDDERS,
  MIN_BIDDERS,
  encodeAllowlistConfig,
  rolesFor,
} from '@interfold/auction-core'
import { designOf, hasProviders } from '@/utils/designs'
import { INPUT_WINDOW_START_BUFFER, STEP_LABELS, useCreateAuction } from '@/hooks/useCreateAuction'
import { useLeaveGuard } from '@/hooks/useLeaveGuard'
import { useWallet } from '@/hooks/useWallet'
import { useServerProvider } from '@/hooks/useServerProvider'
import { parseAllowlist } from '@/utils/allowlist-input'
import { chain } from '@/utils/chain'
import { ALLOWLIST_GATE_ADDRESS } from '@/utils/env-config'
import { formatError } from '@/utils/error-formatting'
import { BID_PROOF_HINT, KEY_GENERATION_HINT, KEY_GENERATION_MINUTES } from '@/utils/estimates'
import { uploadImage } from '@/utils/image'
import { ConnectPrompt } from '@/components/ConnectPrompt'
import { INITIAL_PRICE_FORM, PriceLevelsField, pricesOf } from '@/components/PriceLevelsField'
import Spinner from '@/components/Spinner'
import { WrongChainNote } from '@/components/WrongChainNote'
import { PictureField } from '@/components/PictureField'
import { ProvidersField, checkProviders } from '@/components/ProvidersField'

/** The contract rejects titles outside 1..80 bytes of UTF-8. */
const MAX_TITLE_BYTES = 80

const DURATIONS = [
  { label: '10 minutes', seconds: 10 * 60 },
  { label: '15 minutes', seconds: 15 * 60 },
  { label: '30 minutes', seconds: 30 * 60 },
  { label: '1 hour', seconds: 60 * 60 },
  { label: '2 hours', seconds: 2 * 60 * 60 },
] as const

const NEXT_STEPS = [
  'You approve the fee token and send the request. The wallet asks you to sign each one.',
  `The committee of ciphernodes generates the key. This takes ${KEY_GENERATION_HINT}.`,
  'Bidding opens once the key is published and stays open until the duration ends.',
  'After the window closes the result is computed and decrypted. Share the auction link with the bidders.',
]

/** The next steps of an auction type: a type with mask providers needs their masks before bidding opens. */
function nextSteps(type: AuctionType): string[] {
  if (!hasProviders(type)) return NEXT_STEPS
  return [
    ...NEXT_STEPS.slice(0, 2),
    'Each mask provider sends its mask from the auction page. The demo server sends the mask for its own provider address.',
    'Bidding opens once the key is published and every mask is on chain, and stays open until the duration ends.',
    NEXT_STEPS[3],
  ]
}

/** The minutes that bidding stays open after the key is ready, for a window of `durationSeconds`. The window starts a few minutes after the request. */
const biddingMinutes = (durationSeconds: number): number =>
  Math.round(durationSeconds / 60 + Number(INPUT_WINDOW_START_BUFFER) / 60 - KEY_GENERATION_MINUTES)

const UPLOAD_LABELS = { signing: 'Sign the picture in your wallet…', uploading: 'Uploading the picture…' } as const

const titleBytes = (title: string) => new TextEncoder().encode(title).length

const CreateAuction: React.FC = () => {
  const navigate = useNavigate()
  const { address, wrongChain, ready } = useWallet()
  const create = useCreateAuction(address)
  const { data: walletClient } = useWalletClient({ chainId: chain.id })

  const [title, setTitle] = useState('')
  const [auctionType, setAuctionType] = useState<AuctionType>(AuctionType.FirstPrice)
  const [priceForm, setPriceForm] = useState(INITIAL_PRICE_FORM)
  const [durationSeconds, setDurationSeconds] = useState<number>(DURATIONS[3].seconds)
  const [who, setWho] = useState<'anyone' | 'allowlist'>('anyone')
  const [allowlistText, setAllowlistText] = useState('')
  const [picture, setPicture] = useState<Blob | null>(null)
  const [submitting, setSubmitting] = useState(false)
  // `null` until the creator edits the list: then the default list follows the wallet and the server provider.
  const [editedProviders, setEditedProviders] = useState<string[] | null>(null)
  const serverProvider = useServerProvider()
  const [upload, setUpload] = useState<'signing' | 'uploading' | null>(null)

  const trimmed = title.trim()
  const bytes = titleBytes(trimmed)
  const titleValid = bytes > 0 && bytes <= MAX_TITLE_BYTES
  const priced = pricesOf(priceForm)
  const busy = create.step !== 'idle' || submitting
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
  const defaultProviders = [address, serverProvider].filter((provider, index, all): provider is NonNullable<typeof provider> => {
    return !!provider && all.findIndex((other) => other?.toLowerCase() === provider.toLowerCase()) === index
  })
  const providerRows = editedProviders ?? defaultProviders
  const { providers, error: providersFault } = checkProviders(auctionType, providerRows)
  const canSubmit =
    ready && titleValid && 'prices' in priced && listError === null && providersFault === null && !busy && create.shortfall === null
  useLeaveGuard(busy)

  // Why the button is off, if it is: the first thing the creator must fix. A missing or wrong wallet has its own note above the button.
  const blockReason =
    busy || !ready
      ? null
      : !titleValid
        ? bytes === 0
          ? 'Enter a title.'
          : `Shorten the title to ${MAX_TITLE_BYTES} bytes or less.`
        : 'error' in priced
          ? priced.error
          : providersFault !== null
            ? providersFault
            : listError !== null
              ? listError
              : create.shortfall
                ? 'Add fee tokens to this account first.'
                : null

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    if (!canSubmit || !('prices' in priced)) return
    const gate = who === 'allowlist' ? ALLOWLIST_GATE_ADDRESS : undefined
    setSubmitting(true)
    try {
      const e3Id = await create.create({
        title: trimmed,
        auctionType,
        prices: priced.prices,
        gate: gate ?? zeroAddress,
        gateConfig: gate ? encodeAllowlistConfig(listed.members) : '0x',
        providers,
        durationSeconds,
      })
      if (e3Id === null) return
      // The auction exists now. A failed upload must not undo it: the auction page lets the creator add the picture again.
      let pictureError: string | undefined
      if (picture && walletClient && address) {
        try {
          await uploadImage(walletClient, address, e3Id, picture, setUpload)
        } catch (err) {
          pictureError = formatError(err)
        } finally {
          setUpload(null)
        }
      }
      navigate(`/auction/${e3Id}`, { state: pictureError ? { pictureError } : undefined })
    } finally {
      setSubmitting(false)
    }
  }

  const fee = (amount: bigint) => `${formatUnits(amount, create.feeToken?.decimals ?? 6)} ${create.feeToken?.symbol ?? ''}`.trim()

  return (
    <div className='page !pt-0'>
      <header className='page-intro wide'>
        <h1 className='display'>Create an auction</h1>
        <p className='lede'>
          Choose what the auction reveals, how many price steps a bid can pick from, and the price of each step. Every type takes{' '}
          {MIN_BIDDERS} to {MAX_BIDDERS} bidders.
        </p>
      </header>

      <div className='grid items-start gap-6 lg:grid-cols-[1.4fr_1fr]'>
        <form onSubmit={(event) => void submit(event)} className='card space-y-7'>
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
            <p className={`mt-1 text-xs ${bytes > MAX_TITLE_BYTES ? 'text-negative' : 'text-muted'}`}>
              {bytes}/{MAX_TITLE_BYTES} bytes
            </p>
          </div>

          <PictureField value={picture} onChange={setPicture} disabled={busy} />

          <fieldset className='space-y-3' disabled={busy}>
            <legend className='label'>Auction type</legend>
            {AUCTION_TYPES.map((type) => (
              <label key={type} className={`choice ${auctionType === type ? 'on' : ''}`}>
                <input type='radio' name='auction-type' checked={auctionType === type} onChange={() => setAuctionType(type)} />
                <span className='space-y-1'>
                  <span className='block font-semibold'>{designOf(type).label}</span>
                  <span className='block text-sm text-muted'>{designOf(type).reveals}</span>
                  <span className='block text-sm text-muted'>Trust: {designOf(type).trust}</span>
                  <span className='block font-mono text-xs text-muted'>
                    {MIN_BIDDERS} to {MAX_BIDDERS} bidders · {rolesFor(type).length} ciphertexts for each bid
                  </span>
                </span>
              </label>
            ))}
            <p className='text-sm text-muted'>
              If the top bids tie, the tied bidder who bid first wins. The{' '}
              <Link to='/about' className='linkish'>
                How it works
              </Link>{' '}
              page explains ties.
            </p>
          </fieldset>

          {hasProviders(auctionType) && (
            <ProvidersField
              rows={providerRows}
              onChange={setEditedProviders}
              disabled={busy}
              error={providersFault}
              account={address}
              serverProvider={serverProvider}
            />
          )}

          <PriceLevelsField form={priceForm} onChange={setPriceForm} disabled={busy} />

          <fieldset className='space-y-3' disabled={busy}>
            <legend className='label'>Who can bid</legend>
            <label className={`choice ${who === 'anyone' ? 'on' : ''}`}>
              <input type='radio' name='who' checked={who === 'anyone'} onChange={() => setWho('anyone')} />
              <span className='space-y-1'>
                <span className='block font-semibold'>Anyone</span>
                <span className='block text-sm text-muted'>Any address can bid, up to the limit of the auction type.</span>
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
                <span className='block text-sm text-muted'>
                  Only the addresses you list can bid. The list is public on chain, and the contract checks a Merkle proof of each bid.
                </span>
                {!ALLOWLIST_GATE_ADDRESS && (
                  <span className='block font-mono text-xs text-muted'>Not available: this deployment has no allowlist gate.</span>
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
                <p className={`mt-1 text-xs ${listError && allowlistText.trim() !== '' ? 'text-negative' : 'text-muted'}`}>
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
            <p className='mt-1 text-sm text-muted'>
              The window starts about {Number(INPUT_WINDOW_START_BUFFER) / 60} minutes after the request. Key generation takes{' '}
              {KEY_GENERATION_HINT}, and bids open only once the key is published. A bid proof takes {BID_PROOF_HINT}. Leave room for both.
            </p>
            {biddingMinutes(durationSeconds) < 15 && (
              <p className='note warn mt-2 text-sm'>
                With this duration, bidding stays open for about {Math.max(biddingMinutes(durationSeconds), 0)} minutes. A bidder may not
                finish a proof in time. Choose a longer duration.
              </p>
            )}
          </div>

          {!ready && !wrongChain && <ConnectPrompt>Connect a wallet to create an auction.</ConnectPrompt>}
          {wrongChain && <WrongChainNote>Your wallet is on another network. Switch to {chain.name} to continue.</WrongChainNote>}

          {create.shortfall && (
            <div className='note warn space-y-3'>
              <p>
                The creation fee is <strong>{fee(create.shortfall.needed)}</strong> and this account holds{' '}
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

          <button type='submit' disabled={!canSubmit} className='btn accent block'>
            {busy ? (
              <>
                <Spinner size={14} />{' '}
                {create.step !== 'idle' ? STEP_LABELS[create.step] : upload ? UPLOAD_LABELS[upload] : 'Creating the auction…'}
              </>
            ) : (
              'Create auction'
            )}
          </button>
          {blockReason && (
            <p className='text-center text-sm text-muted' aria-live='polite'>
              {blockReason}
            </p>
          )}
          <p className='text-center text-xs text-muted'>
            Creating an auction pays a creation fee in the fee token{create.feeToken ? ` (${create.feeToken.symbol})` : ''}. The fee pays
            for the encrypted computation of the auction (an E3). Bidders pay only gas.
          </p>
        </form>

        <aside className='card flat space-y-5 lg:sticky lg:top-24'>
          <p className='mono muted'>What happens next</p>
          <ol className='steps'>
            {nextSteps(auctionType).map((text, index) => (
              <li key={text} className='step'>
                <span className='pin'>{index + 1}</span>
                <p className='text-sm text-ink'>{text}</p>
              </li>
            ))}
          </ol>
        </aside>
      </div>
    </div>
  )
}

export default CreateAuction
