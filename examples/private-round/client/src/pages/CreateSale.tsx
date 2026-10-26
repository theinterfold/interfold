// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { MAX_BIDDERS, MAX_LOTS, cost } from '@interfold/private-round'
import { STEP_LABELS, useCreateSale } from '@/hooks/useCreateSale'
import { lookupNote, useTokenInfo } from '@/hooks/useTokenInfo'
import { useWallet } from '@/hooks/useWallet'
import { chain } from '@/utils/chain'
import { PAYMENT_TOKEN_ADDRESS, SALE_TOKEN_ADDRESS } from '@/utils/env-config'
import { formatAmount, parseAmount } from '@/utils/tokens'
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
  'You approve the fee token and the sale token, then send the request. The wallet asks you to sign each.',
  'The program takes the lots from your account when the request is valid. It holds them until the round ends.',
  'The committee of ciphernodes generates the key. This takes several minutes.',
  'Bidding opens once the key is published and stays open until the duration ends. Each bidder locks the same escrow, then bids once for one lot.',
  'After the window closes the round is decided. If the reserve is not met, everyone is refunded and you take back the lots. If it is met, the round clears at one price: bidders above the clearing step claim in phase 1 (2 days), bidders at the step register in phase 2 (2 days) and settle after it.',
  'You withdraw the proceeds. After the 30-day claim window you sweep what no one claimed.',
]

const titleBytes = (title: string) => new TextEncoder().encode(title).length

const CreateSale: React.FC = () => {
  const navigate = useNavigate()
  const { address, wrongChain, ready } = useWallet()
  const create = useCreateSale(address)

  const [title, setTitle] = useState('')
  const [saleTokenText, setSaleTokenText] = useState<string>(SALE_TOKEN_ADDRESS ?? '')
  const [lotText, setLotText] = useState('100')
  const [lots, setLots] = useState(2)
  const [reserveStep, setReserveStep] = useState(0)
  const [minLots, setMinLots] = useState(1)
  const [paymentTokenText, setPaymentTokenText] = useState<string>(PAYMENT_TOKEN_ADDRESS ?? '')
  const [priceForm, setPriceForm] = useState(INITIAL_PRICE_FORM)
  const [durationSeconds, setDurationSeconds] = useState<number>(DURATIONS[2].seconds)

  const saleToken = useTokenInfo(saleTokenText)
  const paymentToken = useTokenInfo(paymentTokenText)
  const saleInfo = saleToken.status === 'ok' ? saleToken.token : null
  const paymentInfo = paymentToken.status === 'ok' ? paymentToken.token : null

  const trimmed = title.trim()
  const bytes = titleBytes(trimmed)
  const titleValid = bytes > 0 && bytes <= MAX_TITLE_BYTES
  const lot = saleInfo ? parseAmount(lotText, saleInfo.decimals) : null
  const lotValid = lot !== null && lot > 0n
  const priced = pricesOf(priceForm, paymentInfo?.decimals ?? 6)
  const levels = priceForm.levels
  // The reserve step and the minimum raise stay inside what the price list and the lots allow.
  const reserve = Math.min(reserveStep, levels - 1)
  const minimum = Math.min(minLots, lots)
  // What the creator deposits, and what each bidder locks: the price of one lot at the highest step.
  const supply = lotValid ? lot * BigInt(lots) : null
  const escrow = lotValid && saleInfo && 'prices' in priced ? cost(lot, priced.prices[priced.prices.length - 1], saleInfo.decimals) : null
  const busy = create.step !== 'idle'
  const canSubmit =
    ready && titleValid && saleInfo !== null && paymentInfo !== null && lotValid && 'prices' in priced && !busy && create.shortfall === null

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    if (!canSubmit || !('prices' in priced) || !saleInfo || !paymentInfo || lot === null) return
    const e3Id = await create.create({
      title: trimmed,
      prices: priced.prices,
      saleToken: saleInfo.address,
      lot,
      lots,
      reserveStep: reserve,
      minLots: minimum,
      paymentToken: paymentInfo.address,
      durationSeconds,
    })
    if (e3Id !== null) navigate(`/sale/${e3Id}`)
  }

  const shortfall = create.shortfall
  const amount = (value: bigint, token: { symbol: string; decimals: number }) =>
    `${formatAmount(value, token.decimals)} ${token.symbol}`.trim()

  return (
    <div className='page'>
      <header className='mb-10 max-w-3xl space-y-4'>
        <p className='mono muted'>New round</p>
        <h1 className='h1'>Create a private round</h1>
        <p className='lede'>
          Sell a few equal lots of a token to up to {MAX_BIDDERS} bidders. Each bidder wants one lot and names, in secret, the highest price
          it will pay. You set a reserve: if too few bidders accept it, nothing sells and everyone is refunded. If the reserve is met, the
          round clears at one price for everyone. Only the outcome and the clearing step become public.
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
              placeholder='What is being sold'
              className='field'
            />
            <p className={`mt-1 text-xs ${bytes > MAX_TITLE_BYTES ? 'text-danger' : 'text-ink-soft'}`}>
              {bytes}/{MAX_TITLE_BYTES} bytes
            </p>
          </div>

          <fieldset className='space-y-5' disabled={busy}>
            <legend className='label'>Token and lots</legend>
            <div>
              <label htmlFor='sale-token' className='label'>
                Sale token address
              </label>
              <input
                id='sale-token'
                value={saleTokenText}
                onChange={(event) => setSaleTokenText(event.target.value)}
                spellCheck={false}
                placeholder='0x…'
                className='field font-mono text-xs'
              />
              <p
                className={`mt-1 text-xs ${saleToken.status === 'invalid' || saleToken.status === 'missing' ? 'text-danger' : 'text-ink-soft'}`}
              >
                {lookupNote(saleToken)}
              </p>
            </div>
            <div className='grid gap-5 sm:grid-cols-2'>
              <div>
                <label htmlFor='lot' className='label'>
                  Lot size{saleInfo ? ` (${saleInfo.symbol})` : ''}
                </label>
                <input
                  id='lot'
                  inputMode='decimal'
                  value={lotText}
                  onChange={(event) => setLotText(event.target.value.trim())}
                  className='field font-mono'
                />
                <p className={`mt-1 text-xs ${saleInfo && !lotValid ? 'text-danger' : 'text-ink-soft'}`}>
                  {saleInfo && !lotValid
                    ? `The lot is a number above zero with at most ${saleInfo.decimals} decimals.`
                    : 'Each bidder buys exactly one lot.'}
                </p>
              </div>
              <div>
                <label htmlFor='lots' className='label'>
                  Lots for sale
                </label>
                <div className='flex items-center gap-4'>
                  <input
                    id='lots'
                    type='range'
                    min={1}
                    max={MAX_LOTS}
                    value={lots}
                    onChange={(event) => setLots(Number(event.target.value))}
                    className='h-2 min-w-0 flex-1 cursor-pointer accent-[var(--accent)] disabled:cursor-not-allowed'
                  />
                  <output className='w-10 shrink-0 text-right font-mono text-2xl'>{lots}</output>
                </div>
                <p className='mt-1 text-xs text-ink-soft'>1 to {MAX_LOTS}. More bidders than lots makes the round compete.</p>
              </div>
            </div>
          </fieldset>

          <fieldset className='space-y-5' disabled={busy}>
            <legend className='label'>Payment token</legend>
            <div>
              <label htmlFor='payment-token' className='label'>
                Payment token address
              </label>
              <input
                id='payment-token'
                value={paymentTokenText}
                onChange={(event) => setPaymentTokenText(event.target.value)}
                spellCheck={false}
                placeholder='0x…'
                className='field font-mono text-xs'
              />
              <p
                className={`mt-1 text-xs ${paymentToken.status === 'invalid' || paymentToken.status === 'missing' ? 'text-danger' : 'text-ink-soft'}`}
              >
                {lookupNote(paymentToken)}
              </p>
            </div>
          </fieldset>

          <PriceLevelsField
            form={priceForm}
            onChange={setPriceForm}
            disabled={busy}
            decimals={paymentInfo?.decimals ?? 6}
            symbol={paymentInfo?.symbol ?? ''}
          />

          <fieldset className='space-y-5' disabled={busy}>
            <legend className='label'>Reserve</legend>
            <div className='grid gap-5 sm:grid-cols-2'>
              <div>
                <label htmlFor='reserve-step' className='label'>
                  Reserve step
                </label>
                <select
                  id='reserve-step'
                  value={reserve}
                  onChange={(event) => setReserveStep(Number(event.target.value))}
                  className='field font-mono'
                >
                  {Array.from({ length: levels }, (_, step) => (
                    <option key={step} value={step}>
                      {step}
                      {'prices' in priced && paymentInfo
                        ? ` (${formatAmount(priced.prices[step], paymentInfo.decimals)} ${paymentInfo.symbol})`
                        : ''}
                    </option>
                  ))}
                </select>
                <p className='mt-1 text-xs text-ink-soft'>
                  The lowest price at which you sell. Nothing sells below it. The round never sells below this step.
                </p>
              </div>
              <div>
                <label htmlFor='min-lots' className='label'>
                  Minimum raise (lots)
                </label>
                <div className='flex items-center gap-4'>
                  <input
                    id='min-lots'
                    type='range'
                    min={1}
                    max={lots}
                    value={minimum}
                    onChange={(event) => setMinLots(Number(event.target.value))}
                    className='h-2 min-w-0 flex-1 cursor-pointer accent-[var(--accent)] disabled:cursor-not-allowed'
                  />
                  <output className='w-10 shrink-0 text-right font-mono text-2xl'>{minimum}</output>
                </div>
                <p className='mt-1 text-xs text-ink-soft'>
                  The fewest bidders at the reserve step or above. With fewer, the round is not met: nothing sells and everyone is refunded.
                </p>
              </div>
            </div>
          </fieldset>

          {saleInfo && paymentInfo && supply !== null && escrow !== null && (
            <dl className='grid gap-4 border border-rule-strong bg-card p-4 sm:grid-cols-3'>
              <div>
                <dt className='mono-sm muted'>You deposit (supply)</dt>
                <dd className='mt-1 font-mono text-sm'>{amount(supply, saleInfo)}</dd>
                <dd className='muted text-xs'>
                  {lots} × {amount(lot as bigint, saleInfo)}
                </dd>
              </div>
              <div>
                <dt className='mono-sm muted'>Each bidder locks (escrow)</dt>
                <dd className='mt-1 font-mono text-sm'>{amount(escrow, paymentInfo)}</dd>
                <dd className='muted text-xs'>The price of one lot at the highest step. The unused part is refunded.</dd>
              </div>
              <div>
                <dt className='mono-sm muted'>Reserve</dt>
                <dd className='mt-1 font-mono text-sm'>
                  {'prices' in priced ? `${formatAmount(priced.prices[reserve], paymentInfo.decimals)} ${paymentInfo.symbol}` : '…'}
                </dd>
                <dd className='muted text-xs'>
                  Met when {minimum} bidder{minimum === 1 ? '' : 's'} accept{minimum === 1 ? 's' : ''} step {reserve} or more.
                </dd>
              </div>
            </dl>
          )}

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
              bidding gets less than the full time. A bidder deposits, proves and submits: leave room for it.
            </p>
          </div>

          {!ready && !wrongChain && <ConnectPrompt>Connect a wallet to create a round.</ConnectPrompt>}
          {wrongChain && <div className='note bad'>Your wallet is on another network. Switch to {chain.name} to continue.</div>}

          {shortfall && (
            <div className='note warn space-y-3'>
              <p>
                {shortfall.kind === 'fee' ? 'The E3 fee is ' : 'The lots are '}
                <strong>{amount(shortfall.needed, shortfall.token)}</strong> and this account holds{' '}
                <strong>{amount(shortfall.balance, shortfall.token)}</strong>.
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
              'Create round'
            )}
          </button>
          <p className='text-center text-xs text-ink-soft'>
            Creating a round pays the E3 fee in the fee token and deposits the lots. Bidders pay only gas, or nothing with a relayer.
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

export default CreateSale
