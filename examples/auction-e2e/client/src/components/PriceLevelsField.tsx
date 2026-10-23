// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { evenPrices, LEVELS, priceListError, type PriceList } from '@shared/layout'

export type PriceMode = 'even' | 'custom'

/** The price inputs of the create form, as typed. `pricesOf` turns them into a price list. */
export interface PriceForm {
  mode: PriceMode
  start: string
  step: string
  /** One entry for each level, used in `custom` mode. */
  custom: readonly string[]
}

const MODE_LABELS: Record<PriceMode, string> = {
  even: 'Even steps',
  custom: 'Custom list',
}

/** 1-2-5 steps over five decades: fine at the low end, wide at the top. */
const SCALE_125 = ['1', '2', '5', '10', '20', '50', '100', '200', '500', '1000', '2000', '5000', '10000', '20000', '50000', '100000']

const WHOLE = /^\d+$/

export const INITIAL_PRICE_FORM: PriceForm = {
  mode: 'even',
  start: '0',
  step: '1',
  custom: evenPrices(0n, 1n).map(String),
}

/** The price list of `form`, or the reason it has none. */
export function pricesOf(form: PriceForm): { prices: PriceList } | { error: string } {
  if (form.mode === 'even') {
    if (!WHOLE.test(form.start)) return { error: 'The start price is a whole number of zero or more.' }
    if (!WHOLE.test(form.step) || BigInt(form.step) === 0n) return { error: 'The step is a whole number above zero.' }
    return { prices: evenPrices(BigInt(form.start), BigInt(form.step)) }
  }
  const blank = form.custom.findIndex((text) => !WHOLE.test(text))
  if (blank >= 0) return { error: `Level ${blank} needs a whole number of zero or more.` }
  const prices = form.custom.map(BigInt)
  const error = priceListError(prices)
  return error ? { error: `${error}.` } : { prices }
}

interface Props {
  form: PriceForm
  onChange: (form: PriceForm) => void
  disabled: boolean
}

export const PriceLevelsField: React.FC<Props> = ({ form, onChange, disabled }) => {
  const result = pricesOf(form)

  const selectMode = (mode: PriceMode) => {
    // Switching to a custom list starts from the even prices on screen, so they can be edited.
    if (mode === 'custom' && form.mode === 'even' && 'prices' in result) {
      onChange({ ...form, mode, custom: result.prices.map(String) })
    } else {
      onChange({ ...form, mode })
    }
  }
  const setLevel = (level: number, text: string) => onChange({ ...form, custom: form.custom.map((old, l) => (l === level ? text : old)) })

  return (
    <fieldset className='space-y-3' disabled={disabled}>
      <legend className='label'>Price levels</legend>
      <div className='grid grid-cols-2 gap-2' role='radiogroup' aria-label='Price levels'>
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

      {form.mode === 'even' ? (
        <div className='grid grid-cols-2 gap-3'>
          <div>
            <label htmlFor='price-start' className='label'>
              Start price
            </label>
            <input
              id='price-start'
              inputMode='numeric'
              value={form.start}
              onChange={(event) => onChange({ ...form, start: event.target.value.trim() })}
              className='field font-mono'
            />
          </div>
          <div>
            <label htmlFor='price-step' className='label'>
              Step
            </label>
            <input
              id='price-step'
              inputMode='numeric'
              value={form.step}
              onChange={(event) => onChange({ ...form, step: event.target.value.trim() })}
              className='field font-mono'
            />
          </div>
        </div>
      ) : (
        <div className='space-y-2'>
          <div className='grid grid-cols-2 gap-2 sm:grid-cols-4'>
            {form.custom.map((text, level) => (
              <label key={level} className='flex items-center gap-2'>
                <span className='w-6 shrink-0 text-right font-mono text-xs text-ink-soft'>{level}</span>
                <input
                  aria-label={`Price of level ${level}`}
                  inputMode='numeric'
                  value={text}
                  onChange={(event) => setLevel(level, event.target.value.trim())}
                  className='field !px-2 !py-1.5 font-mono text-sm'
                />
              </label>
            ))}
          </div>
          <button type='button' onClick={() => onChange({ ...form, custom: SCALE_125 })} className='btn sm'>
            Fill a 1-2-5 scale
          </button>
        </div>
      )}

      <p className={`text-xs ${'prices' in result ? 'text-ink-soft' : 'text-danger'}`}>
        {'prices' in result
          ? `A bid is one of ${LEVELS} levels, from ${result.prices[0].toLocaleString('en-US')} up to ${result.prices[
              LEVELS - 1
            ].toLocaleString('en-US')}. The levels can be uneven: use small steps where you expect the bids, and large steps above.`
          : result.error}
      </p>
    </fieldset>
  )
}
