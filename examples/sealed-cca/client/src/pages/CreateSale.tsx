// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { MAX_BIDDERS } from '@interfold/sealed-cca'
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
  'The program takes the supply from your account when the request is valid. It holds the supply until the sale ends.',
  'The committee of ciphernodes generates the key. This takes several minutes.',
  'Bidding opens once the key is published and stays open until the duration ends. Each bidder locks the same escrow with its bid.',
  'After the window closes the sale clears at one price. Bidders claim their tokens and refunds within 30 days. You withdraw the proceeds and any unsold tokens, and after 30 days you sweep what no one claimed.',
]

const titleBytes = (title: string) => new TextEncoder().encode(title).length

const CreateSale: React.FC = () => {
  const navigate = useNavigate()
  const { address, wrongChain, ready } = useWallet()
  const create = useCreateSale(address)

  const [title, setTitle] = useState('')
  const [saleTokenText, setSaleTokenText] = useState<string>(SALE_TOKEN_ADDRESS ?? '')
  const [supplyText, setSupplyText] = useState('1000')
  const [paymentTokenText, setPaymentTokenText] = useState<string>(PAYMENT_TOKEN_ADDRESS ?? '')
  const [escrowText, setEscrowText] = useState('100')
  const [priceForm, setPriceForm] = useState(INITIAL_PRICE_FORM)
  const [durationSeconds, setDurationSeconds] = useState<number>(DURATIONS[2].seconds)

  const saleToken = useTokenInfo(saleTokenText)
  const paymentToken = useTokenInfo(paymentTokenText)
  const saleInfo = saleToken.status === 'ok' ? saleToken.token : null
  const paymentInfo = paymentToken.status === 'ok' ? paymentToken.token : null

  const trimmed = title.trim()
  const bytes = titleBytes(trimmed)
  const titleValid = bytes > 0 && bytes <= MAX_TITLE_BYTES
  const supply = saleInfo ? parseAmount(supplyText, saleInfo.decimals) : null
  const escrow = paymentInfo ? parseAmount(escrowText, paymentInfo.decimals) : null
  const supplyValid = supply !== null && supply > 0n
  const escrowValid = escrow !== null && escrow > 0n
  const priced = pricesOf(priceForm, paymentInfo?.decimals ?? 6)
  const busy = create.step !== 'idle'
  const canSubmit =
    ready &&
    titleValid &&
    saleInfo !== null &&
    paymentInfo !== null &&
    supplyValid &&
    escrowValid &&
    'prices' in priced &&
    !busy &&
    create.shortfall === null

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    if (!canSubmit || !('prices' in priced) || !saleInfo || !paymentInfo || supply === null || escrow === null) return
    const e3Id = await create.create({
      title: trimmed,
      prices: priced.prices,
      saleToken: saleInfo.address,
      supply,
      paymentToken: paymentInfo.address,
      escrow,
      durationSeconds,
    })
    if (e3Id !== null) navigate(`/sale/${e3Id}`)
  }

  const shortfall = create.shortfall
  const amount = (value: bigint, token: { symbol: string; decimals: number }) =>
    `${formatAmount(value, token.decimals)} ${token.symbol}`.trim()
  // Tokens one escrow buys at each step, as a hint of what the prices mean.
  const unit = saleInfo ? 10n ** BigInt(saleInfo.decimals) : null

  return (
    <div className='page !pt-0'>
      <header className='page-intro wide'>
        <h1 className='display'>Create a token sale</h1>
        <p className='lede'>
          Sell a fixed supply of a token in one sealed batch. Each bidder picks its highest price and locks the same escrow. The sale clears
          at one price for everyone, up to {MAX_BIDDERS} bidders.
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
              placeholder='What is being sold'
              className='field'
            />
            <p className={`mt-1 text-xs ${bytes > MAX_TITLE_BYTES ? 'text-negative' : 'text-muted'}`}>
              {bytes}/{MAX_TITLE_BYTES} bytes
            </p>
          </div>

          <fieldset className='space-y-5' disabled={busy}>
            <legend className='label'>Sale token and supply</legend>
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
                className={`mt-1 text-xs ${saleToken.status === 'invalid' || saleToken.status === 'missing' ? 'text-negative' : 'text-muted'}`}
              >
                {lookupNote(saleToken)}
              </p>
            </div>
            <div>
              <label htmlFor='supply' className='label'>
                Supply{saleInfo ? ` (${saleInfo.symbol})` : ''}
              </label>
              <input
                id='supply'
                inputMode='decimal'
                value={supplyText}
                onChange={(event) => setSupplyText(event.target.value.trim())}
                className='field font-mono'
              />
              <p className={`mt-1 text-xs ${saleInfo && !supplyValid ? 'text-negative' : 'text-muted'}`}>
                {saleInfo && !supplyValid
                  ? `The supply is a number above zero with at most ${saleInfo.decimals} decimals.`
                  : 'The program takes this supply from your account when the sale is created.'}
              </p>
            </div>
          </fieldset>

          <fieldset className='space-y-5' disabled={busy}>
            <legend className='label'>Payment token and escrow</legend>
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
                className={`mt-1 text-xs ${paymentToken.status === 'invalid' || paymentToken.status === 'missing' ? 'text-negative' : 'text-muted'}`}
              >
                {lookupNote(paymentToken)}
              </p>
            </div>
            <div>
              <label htmlFor='escrow' className='label'>
                Escrow of each bid{paymentInfo ? ` (${paymentInfo.symbol})` : ''}
              </label>
              <input
                id='escrow'
                inputMode='decimal'
                value={escrowText}
                onChange={(event) => setEscrowText(event.target.value.trim())}
                className='field font-mono'
              />
              <p className={`mt-1 text-xs ${paymentInfo && !escrowValid ? 'text-negative' : 'text-muted'}`}>
                {paymentInfo && !escrowValid
                  ? `The escrow is a number above zero with at most ${paymentInfo.decimals} decimals.`
                  : 'Every bidder locks this amount, whatever its price. A bid buys at most the escrow divided by the clearing price. The rest is refunded.'}
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

          {saleInfo && paymentInfo && escrowValid && 'prices' in priced && unit !== null && escrow !== null && (
            <div className='space-y-2'>
              <p className='label !mb-0'>What one escrow buys</p>
              <div className='overflow-x-auto'>
                <table className='w-full text-left font-mono text-xs'>
                  <thead className='text-muted'>
                    <tr>
                      <th className='pr-4 font-normal'>Step</th>
                      <th className='pr-4 font-normal'>Price ({paymentInfo.symbol})</th>
                      <th className='font-normal'>Tokens for one escrow ({saleInfo.symbol})</th>
                    </tr>
                  </thead>
                  <tbody>
                    {priced.prices.map((price, step) => (
                      <tr key={step}>
                        <td className='pr-4'>{step}</td>
                        <td className='pr-4'>{formatAmount(price, paymentInfo.decimals)}</td>
                        <td>{formatAmount((escrow * unit) / price, saleInfo.decimals)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
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
            <p className='mt-1 text-xs text-muted'>
              The duration counts from the request. Key generation takes several minutes and bids open only once the key is published, so
              bidding gets less than the full time. A bidder deposits, proves and submits: leave room for it.
            </p>
          </div>

          {!ready && !wrongChain && <ConnectPrompt>Connect a wallet to create a sale.</ConnectPrompt>}
          {wrongChain && <div className='note bad'>Your wallet is on another network. Switch to {chain.name} to continue.</div>}

          {shortfall && (
            <div className='note warn space-y-3'>
              <p>
                {shortfall.kind === 'fee' ? 'The E3 fee is ' : 'The supply is '}
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

          <button type='submit' disabled={!canSubmit} className='btn accent block'>
            {busy ? (
              <>
                <Spinner size={14} /> {STEP_LABELS[create.step as Exclude<typeof create.step, 'idle'>]}
              </>
            ) : (
              'Create sale'
            )}
          </button>
          <p className='text-center text-xs text-muted'>
            Creating a sale pays the E3 fee in the fee token and deposits the supply. Bidders pay only gas.
          </p>
        </form>

        <aside className='card flat space-y-5 lg:sticky lg:top-24'>
          <p className='mono muted'>What happens next</p>
          <ol className='steps'>
            {NEXT_STEPS.map((text, index) => (
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

export default CreateSale
