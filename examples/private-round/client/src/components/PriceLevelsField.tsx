// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { LEVELS, MIN_LEVELS, type PriceList, linearPrices, priceListError } from '@interfold/private-round'
import { formatAmount, parseAmount } from '@/utils/tokens'

export type PriceMode = 'linear' | 'custom'

/** The price inputs of the create form, as typed, in payment tokens per whole sale token. `pricesOf` turns them into a price list. */
export interface PriceForm {
  /** The number of price steps, `MIN_LEVELS` to `LEVELS`. A bid is one of them. */
  levels: number
  mode: PriceMode
  floor: string
  cap: string
  /** One entry for each step (`levels` entries), used in `custom` mode. */
  custom: readonly string[]
}

const MODE_LABELS: Record<PriceMode, string> = {
  linear: 'Linear, floor to cap',
  custom: 'Custom list',
}

const DEFAULT_LEVELS = 8

export const INITIAL_PRICE_FORM: PriceForm = {
  levels: DEFAULT_LEVELS,
  mode: 'linear',
  floor: '0.5',
  cap: '2',
  custom: [],
}

/** `custom` cut or grown to `levels` entries. A new entry repeats the last one, which the user then raises. */
function resized(custom: readonly string[], levels: number): string[] {
  const next = custom.slice(0, levels)
  while (next.length < levels) next.push(next[next.length - 1] ?? '')
  return next
}

/** The price list of `form` in payment-token base units, or the reason it has none. */
export function pricesOf(form: PriceForm, decimals: number): { prices: PriceList } | { error: string } {
  let prices: bigint[]
  if (form.mode === 'linear') {
    const floor = parseAmount(form.floor, decimals)
    const cap = parseAmount(form.cap, decimals)
    if (floor === null) return { error: `The floor is a number with at most ${decimals} decimals.` }
    if (cap === null) return { error: `The cap is a number with at most ${decimals} decimals.` }
    if (cap <= floor) return { error: 'The cap must be above the floor.' }
    prices = linearPrices(floor, cap, form.levels)
  } else {
    const entries = resized(form.custom, form.levels).map((text) => parseAmount(text, decimals))
    const bad = entries.findIndex((entry) => entry === null)
    if (bad >= 0) return { error: `Step ${bad} needs a number with at most ${decimals} decimals.` }
    prices = entries as bigint[]
  }
  const error = priceListError(prices)
  return error ? { error: `${error}.` } : { prices }
}

interface Props {
  form: PriceForm
  onChange: (form: PriceForm) => void
  disabled: boolean
  /** Decimals of the payment token: the prices are typed in whole payment tokens. */
  decimals: number
  symbol: string
}

export const PriceLevelsField: React.FC<Props> = ({ form, onChange, disabled, decimals, symbol }) => {
  const result = pricesOf(form, decimals)
  const custom = resized(form.custom, form.levels)

  const selectMode = (mode: PriceMode) => {
    // Switching to a custom list starts from the linear prices on screen, so they can be edited.
    if (mode === 'custom' && form.mode === 'linear' && 'prices' in result) {
      onChange({ ...form, mode, custom: result.prices.map((price) => formatAmount(price, decimals, decimals).replace(/,/g, '')) })
    } else {
      onChange({ ...form, mode })
    }
  }
  const setLevels = (levels: number) => onChange({ ...form, levels, custom: resized(form.custom, levels) })
  const setPrice = (step: number, text: string) => onChange({ ...form, custom: custom.map((old, s) => (s === step ? text : old)) })

  return (
    <div className='space-y-7'>
      <fieldset disabled={disabled}>
        <legend className='label'>Number of price steps</legend>
        <div className='flex items-center gap-4'>
          <input
            type='range'
            aria-label='Number of price steps'
            min={MIN_LEVELS}
            max={LEVELS}
            value={form.levels}
            onChange={(event) => setLevels(Number(event.target.value))}
            className='h-2 min-w-0 flex-1 cursor-pointer accent-[var(--accent)] disabled:cursor-not-allowed'
          />
          <output className='w-10 shrink-0 text-right font-mono text-2xl'>{form.levels}</output>
        </div>
        <p className='mt-1 text-xs text-ink-soft'>
          A bidder picks the highest price it will pay: one of these steps, numbered 0 to {form.levels - 1}. Choose {MIN_LEVELS} to {LEVELS}
          .
        </p>
      </fieldset>

      <fieldset className='space-y-3' disabled={disabled}>
        <legend className='label'>
          Price of one {`whole sale token`}, in {symbol || 'payment tokens'}
        </legend>
        <div className='grid grid-cols-2 gap-2' role='radiogroup' aria-label='How the prices are set'>
          {(Object.keys(MODE_LABELS) as PriceMode[]).map((mode) => (
            <button
              key={mode}
              type='button'
              role='radio'
              aria-checked={form.mode === mode}
              onClick={() => selectMode(mode)}
              className={`border px-3 py-2 text-sm transition-colors disabled:cursor-not-allowed ${
                form.mode === mode ? 'border-ink bg-ink text-paper' : 'border-rule-strong bg-card hover:border-ink'
              }`}
            >
              {MODE_LABELS[mode]}
            </button>
          ))}
        </div>

        {form.mode === 'linear' ? (
          <div className='grid grid-cols-2 gap-3'>
            <div>
              <label htmlFor='price-floor' className='label'>
                Floor (step 0)
              </label>
              <input
                id='price-floor'
                inputMode='decimal'
                value={form.floor}
                onChange={(event) => onChange({ ...form, floor: event.target.value.trim() })}
                className='field font-mono'
              />
            </div>
            <div>
              <label htmlFor='price-cap' className='label'>
                Cap (step {form.levels - 1})
              </label>
              <input
                id='price-cap'
                inputMode='decimal'
                value={form.cap}
                onChange={(event) => onChange({ ...form, cap: event.target.value.trim() })}
                className='field font-mono'
              />
            </div>
          </div>
        ) : (
          <div className='space-y-2'>
            <div className='grid grid-cols-2 gap-2 sm:grid-cols-4'>
              {custom.map((text, step) => (
                <label key={step} className='flex items-center gap-2'>
                  <span className='w-6 shrink-0 text-right font-mono text-xs text-ink-soft'>{step}</span>
                  <input
                    aria-label={`Price of step ${step}`}
                    inputMode='decimal'
                    value={text}
                    onChange={(event) => setPrice(step, event.target.value.trim())}
                    className='field !px-2 !py-1.5 font-mono text-sm'
                  />
                </label>
              ))}
            </div>
          </div>
        )}

        <p className={`text-xs ${'prices' in result ? 'text-ink-soft' : 'text-danger'}`}>
          {'prices' in result
            ? `${form.levels} steps: ${result.prices.map((price) => formatAmount(price, decimals)).join(', ')}.`
            : result.error}
        </p>
      </fieldset>
    </div>
  )
}
