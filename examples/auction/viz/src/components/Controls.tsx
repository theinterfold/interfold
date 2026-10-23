// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { Profile } from '@designs'
import { PROFILES } from '@designs'
import { randomBids, randomSeed, type Params } from '../lib/params'
import { MAX_BIDDERS, MAX_LEVELS, MIN_BIDDERS, MIN_LEVELS } from '../lib/simulate'

interface ControlsProps {
  params: Params
  /** The tie priority of the selected design, or `null` when it breaks ties by index. */
  tiePriority: number[] | null
  onChange: (patch: Partial<Params>) => void
}

interface NumberControlProps {
  id: string
  label: string
  value: number
  min: number
  max: number
  onChange: (value: number) => void
}

function NumberControl({ id, label, value, min, max, onChange }: NumberControlProps) {
  return (
    <div>
      <label className='label' htmlFor={id}>
        {label}
      </label>
      <div className='flex items-center gap-3'>
        <input id={id} type='range' min={min} max={max} value={value} onChange={(event) => onChange(Number(event.target.value))} />
        <input
          aria-label={label}
          type='number'
          className='field !w-20 text-center'
          min={min}
          max={max}
          value={value}
          onChange={(event) => {
            const next = Number(event.target.value)
            if (Number.isInteger(next)) onChange(Math.min(max, Math.max(min, next)))
          }}
        />
      </div>
    </div>
  )
}

const profileChoices = Object.keys(PROFILES) as Profile[]

export function Controls({ params, tiePriority, onChange }: ControlsProps) {
  const { profile, bidders, levels, bids, seed } = params
  const setBid = (index: number, bid: number) => onChange({ bids: bids.map((old, i) => (i === index ? bid : old)) })
  const tieOrder = tiePriority === null ? [] : tiePriority.map((_, i) => i).sort((a, b) => tiePriority[b] - tiePriority[a])

  return (
    <div className='card flex flex-col gap-6'>
      <div className='grid gap-6 md:grid-cols-2 lg:grid-cols-4'>
        <NumberControl
          id='bidders'
          label='Bidders'
          value={bidders}
          min={MIN_BIDDERS}
          max={MAX_BIDDERS}
          onChange={(value) => onChange({ bidders: value })}
        />
        <NumberControl
          id='levels'
          label='Price levels'
          value={levels}
          min={MIN_LEVELS}
          max={MAX_LEVELS}
          onChange={(value) => onChange({ levels: value })}
        />
        <div>
          <label className='label' htmlFor='seed'>
            Seed (masks)
          </label>
          <div className='flex gap-2'>
            <input
              id='seed'
              type='number'
              className='field'
              min={0}
              value={seed}
              onChange={(event) => {
                const next = Number(event.target.value)
                if (Number.isInteger(next) && next >= 0) onChange({ seed: next })
              }}
            />
            <button type='button' className='btn ghost sm' onClick={() => onChange({ seed: randomSeed() })}>
              Re-roll
            </button>
          </div>
        </div>
        <div>
          <span className='label'>Profile</span>
          <div className='flex gap-2' role='group' aria-label='Profile'>
            {profileChoices.map((choice) => (
              <button
                key={choice}
                type='button'
                aria-pressed={profile === choice}
                className={`btn sm ${profile === choice ? '' : 'ghost'}`}
                onClick={() => onChange({ profile: choice })}
              >
                {choice} · N={PROFILES[choice].degree}
              </button>
            ))}
          </div>
        </div>
      </div>

      {profile === 'demo' && (
        <div className='note warn'>
          The demo profile has N = 16384 slots and t = 65537. Runs are slower. The grids show the regions only, as in the toy profile. The
          other slots are counted below each grid.
        </div>
      )}

      {tiePriority !== null && (
        <div className='flex flex-col gap-2'>
          <span className='label'>Tie priority (drawn after the bids close)</span>
          <div className='flex flex-wrap items-center gap-3'>
            <span className='font-mono text-[13px]'>[{tiePriority.join(', ')}]</span>
            <span className='text-[13px] text-ink-soft'>A tie goes to:</span>
            <span className='flex flex-wrap items-center gap-1'>
              {tieOrder.map((bidder, position) => (
                <span key={bidder} className='flex items-center gap-1'>
                  {position > 0 && <span className='text-ink-soft'>›</span>}
                  <span className={`tag ${position === 0 ? 'live' : 'muted'}`}>bidder {bidder}</span>
                </span>
              ))}
            </span>
            <button type='button' className='btn ghost sm' onClick={() => onChange({ tieSeed: randomSeed() })}>
              Re-draw
            </button>
          </div>
        </div>
      )}

      <div className='flex flex-col gap-3'>
        <div className='flex flex-wrap items-center justify-between gap-3'>
          <span className='label !mb-0'>Bids (0 to {levels - 1})</span>
          <div className='flex flex-wrap gap-2'>
            <button type='button' className='btn ghost sm' onClick={() => onChange({ bids: randomBids(levels) })}>
              Random bids
            </button>
            <button
              type='button'
              className='btn ghost sm'
              onClick={() => {
                const top = Math.max(...bids.slice(0, bidders))
                onChange({ bids: bids.map((bid, i) => (i < 2 ? top : bid)) })
              }}
            >
              Tie for highest
            </button>
          </div>
        </div>
        <div className='grid gap-x-8 gap-y-3 md:grid-cols-2'>
          {bids.slice(0, bidders).map((bid, index) => (
            <div key={index} className='flex items-center gap-3'>
              <label htmlFor={`bid-${index}`} className='mono-sm w-16 flex-none'>
                Bidder {index}
              </label>
              <input
                id={`bid-${index}`}
                type='range'
                min={0}
                max={levels - 1}
                value={bid}
                onChange={(event) => setBid(index, Number(event.target.value))}
              />
              <span className='w-8 flex-none text-right font-mono text-[14px]'>{bid}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
