// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { MAX_BIDDERS, MAX_BUDGET_UNITS, MAX_TIERS, MAX_TITLE_BYTES, tierListError } from '@interfold/token-launch'
import { STEP_LABELS, useCreateSale } from '@/hooks/useCreateSale'
import { lookupNote, useTokenInfo } from '@/hooks/useTokenInfo'
import { useWallet } from '@/hooks/useWallet'
import { chain } from '@/utils/chain'
import { PAYMENT_TOKEN_ADDRESS, SALE_TOKEN_ADDRESS } from '@/utils/env-config'
import { formatAmount, parseAmount } from '@/utils/tokens'
import { ConnectPrompt } from '@/components/ConnectPrompt'
import { INITIAL_PRICE_FORM, PriceLevelsField, pricesOf } from '@/components/PriceLevelsField'
import Spinner from '@/components/Spinner'

const DURATIONS = [
  { label: '15 minutes', seconds: 15 * 60 },
  { label: '30 minutes', seconds: 30 * 60 },
  { label: '1 hour', seconds: 60 * 60 },
  { label: '2 hours', seconds: 2 * 60 * 60 },
] as const

const NEXT_STEPS = [
  'You approve the fee token and the sale token. The wallet asks you to sign each.',
  'You send two requests, one for round 1 and one for round 2. The program takes the supply with request 1. Each request pays one Interfold fee.',
  'The committee makes one key for each round. This takes several minutes.',
  'Bidding opens when both keys exist. It stays open until the duration ends. Each bidder locks an escrow tier and bids a private budget and a private max price.',
  'After the window closes, two short rounds reveal a few budget sums. The sale then clears at one price.',
  'Bidders claim to fresh addresses within 30 days. You withdraw the proceeds and the unsold tokens. After 30 days you sweep what is left.',
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
  const [unitText, setUnitText] = useState('1')
  const [tierTexts, setTierTexts] = useState<string[]>(['10', '50', '200'])
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
  const budgetUnit = paymentInfo ? parseAmount(unitText, paymentInfo.decimals) : null
  const supplyValid = supply !== null && supply > 0n
  const unitValid = budgetUnit !== null && budgetUnit > 0n
  const tiers = tierTexts.map((text) => (/^\d+$/.test(text) ? Number(text) : Number.NaN))
  const tierError = tierListError(tiers)
  const priced = pricesOf(priceForm, paymentInfo?.decimals ?? 6)
  const busy = create.step !== 'idle'
  const canSubmit =
    ready &&
    titleValid &&
    saleInfo !== null &&
    paymentInfo !== null &&
    supplyValid &&
    unitValid &&
    tierError === null &&
    'prices' in priced &&
    !busy &&
    create.shortfall === null

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    if (!canSubmit || !('prices' in priced) || !saleInfo || !paymentInfo || supply === null || budgetUnit === null) return
    const saleId = await create.create({
      title: trimmed,
      prices: priced.prices,
      saleToken: saleInfo.address,
      supply,
      paymentToken: paymentInfo.address,
      budgetUnit,
      tiers,
      durationSeconds,
    })
    if (saleId !== null) navigate(`/sale/${saleId}`)
  }

  const shortfall = create.shortfall
  const amount = (value: bigint, token: { symbol: string; decimals: number }) =>
    `${formatAmount(value, token.decimals)} ${token.symbol}`.trim()
  const saleUnit = saleInfo ? 10n ** BigInt(saleInfo.decimals) : null
  const setTier = (index: number, text: string) => setTierTexts(tierTexts.map((old, i) => (i === index ? text.trim() : old)))

  return (
    <div className='page'>
      <header className='mb-10 max-w-3xl space-y-4'>
        <p className='mono muted'>New sale</p>
        <h1 className='h1'>Create a token launch</h1>
        <p className='lede'>
          Sell a fixed supply of a token at one price. Each bidder keeps its budget and its max price private. A sale takes up to{' '}
          {MAX_BIDDERS} bids.
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
                className={`mt-1 text-xs ${saleToken.status === 'invalid' || saleToken.status === 'missing' ? 'text-danger' : 'text-ink-soft'}`}
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
              <p className={`mt-1 text-xs ${saleInfo && !supplyValid ? 'text-danger' : 'text-ink-soft'}`}>
                {saleInfo && !supplyValid
                  ? `The supply is a number above zero with at most ${saleInfo.decimals} decimals.`
                  : 'The program takes this supply from your account when you send request 1.'}
              </p>
            </div>
          </fieldset>

          <fieldset className='space-y-5' disabled={busy}>
            <legend className='label'>Payment token, budget unit and escrow tiers</legend>
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
            <div>
              <label htmlFor='unit' className='label'>
                Budget unit{paymentInfo ? ` (${paymentInfo.symbol})` : ''}
              </label>
              <input
                id='unit'
                inputMode='decimal'
                value={unitText}
                onChange={(event) => setUnitText(event.target.value.trim())}
                className='field font-mono'
              />
              <p className={`mt-1 text-xs ${paymentInfo && !unitValid ? 'text-danger' : 'text-ink-soft'}`}>
                {paymentInfo && !unitValid
                  ? `The budget unit is a number above zero with at most ${paymentInfo.decimals} decimals.`
                  : `A bidder gives its budget in whole budget units, from 1 to ${MAX_BUDGET_UNITS}.`}
              </p>
            </div>
            <div className='space-y-2'>
              <p className='label !mb-0'>Escrow tiers (budget units)</p>
              <div className='grid grid-cols-2 gap-3 sm:grid-cols-4'>
                {tierTexts.map((text, index) => (
                  <div key={index} className='flex items-center gap-1'>
                    <input
                      aria-label={`Escrow tier ${index}`}
                      inputMode='numeric'
                      value={text}
                      onChange={(event) => setTier(index, event.target.value)}
                      className='field font-mono'
                    />
                    {tierTexts.length > 1 && (
                      <button
                        type='button'
                        aria-label={`Remove tier ${index}`}
                        onClick={() => setTierTexts(tierTexts.filter((_, i) => i !== index))}
                        className='btn ghost sm'
                      >
                        ×
                      </button>
                    )}
                  </div>
                ))}
              </div>
              {tierTexts.length < MAX_TIERS && (
                <button type='button' onClick={() => setTierTexts([...tierTexts, ''])} className='btn ghost sm'>
                  Add a tier
                </button>
              )}
              <p className={`text-xs ${tierError === null ? 'text-ink-soft' : 'text-danger'}`}>
                {tierError === null && paymentInfo && budgetUnit !== null
                  ? `A bidder locks one tier. Its budget is at most that tier. Tiers lock ${tiers
                      .map((tier) => amount(BigInt(tier) * budgetUnit, paymentInfo))
                      .join(', ')}. Everyone sees the tier of a bid, so use few tiers.`
                  : (tierError ?? 'A bidder locks one tier. Its budget is at most that tier.')}
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

          {saleInfo && paymentInfo && unitValid && 'prices' in priced && saleUnit !== null && budgetUnit !== null && (
            <div className='space-y-2'>
              <p className='label !mb-0'>What one budget unit buys</p>
              <div className='overflow-x-auto'>
                <table className='w-full text-left font-mono text-xs'>
                  <thead className='text-ink-soft'>
                    <tr>
                      <th className='pr-4 font-normal'>Step</th>
                      <th className='pr-4 font-normal'>Price ({paymentInfo.symbol})</th>
                      <th className='font-normal'>Tokens for one unit ({saleInfo.symbol})</th>
                    </tr>
                  </thead>
                  <tbody>
                    {priced.prices.map((price, step) => (
                      <tr key={step}>
                        <td className='pr-4'>{step}</td>
                        <td className='pr-4'>{formatAmount(price, paymentInfo.decimals)}</td>
                        <td>{formatAmount((budgetUnit * saleUnit) / price, saleInfo.decimals)}</td>
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
            <p className='mt-1 text-xs text-ink-soft'>
              Both requests use this window. Key generation takes several minutes and bids open only when both keys exist, so bidding gets
              less than the full time. A bidder proves in the browser: leave room for it.
            </p>
          </div>

          {!ready && !wrongChain && <ConnectPrompt>Connect a wallet to create a sale.</ConnectPrompt>}
          {wrongChain && <div className='note bad'>Your wallet is on another network. Switch to {chain.name} to continue.</div>}

          {shortfall && (
            <div className='note warn space-y-3'>
              <p>
                {shortfall.kind === 'fee' ? 'The two E3 fees are ' : 'The supply is '}
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
              'Create sale (two requests)'
            )}
          </button>
          <p className='text-center text-xs text-ink-soft'>
            A sale is two E3 runs: round 1 and round 2. You pay two Interfold fees in the fee token and you deposit the supply. Your wallet
            asks you to confirm two requests. Bidders pay only the escrow and gas, or no gas with the relayer.
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
