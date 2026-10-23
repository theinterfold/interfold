// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { designNames, designs, type Profile } from '@designs'
import { explanations } from '../lib/designInfo'
import { MAX_BIDDERS, MIN_BIDDERS, measureCost } from '../lib/simulate'
import { CostChart } from './CostChart'
import { DesignFacts } from './DesignFacts'
import { Section } from './Section'

interface OverviewProps {
  profile: Profile
  bidders: number
  levels: number
  selected: string
  onOpen: (design: string) => void
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className='flex flex-col'>
      <span className='mono-sm text-ink-soft'>{label}</span>
      <span className='font-serif text-[26px] leading-none'>{value}</span>
    </div>
  )
}

export function Overview({ profile, bidders, levels, selected, onOpen }: OverviewProps) {
  return (
    <Section
      id='overview'
      kicker='01 · Overview'
      title='Ten designs, one question'
      intro={`Each design computes a sealed-bid auction on bids that stay hidden. They differ in what the output reveals and in what the program costs. Costs are measured for ${bidders} bidders and ${levels} price levels. Click a design to open it in the playground.`}
    >
      <div className='grid gap-5 md:grid-cols-2'>
        {designNames.map((name) => {
          const design = designs[name]
          const cost = measureCost(name, profile, bidders, levels)
          return (
            <article
              key={name}
              onClick={() => onOpen(name)}
              className={`card link flex cursor-pointer flex-col gap-4 ${name === selected ? 'tint' : ''}`}
            >
              <div className='flex flex-wrap items-baseline justify-between gap-2'>
                <h3 className='h3 font-mono text-[18px]'>{name}</h3>
                {name === selected && <span className='tag live'>In the playground</span>}
              </div>
              <p className='m-0 text-[14px] leading-snug text-ink-2'>
                <span className='mono-sm text-ink-soft'>Reveals · </span>
                {design.disclosure}
              </p>
              <DesignFacts design={design} />
              <div className='hr-soft' />
              {cost.ok ? (
                <div className='flex flex-wrap gap-x-8 gap-y-2'>
                  <Stat label='ct×ct' value={cost.cost.ciphertextProducts} />
                  <Stat label='ct×pt' value={cost.cost.plaintextProducts} />
                  <Stat label='depth' value={cost.cost.depth} />
                  <Stat label='ciphertexts / bidder' value={design.inputNames.length} />
                </div>
              ) : (
                <div className='note bad'>{cost.error.message}</div>
              )}
              <p className='m-0 line-clamp-3 text-[13px] text-ink-soft'>{explanations[name]}</p>
              <button
                type='button'
                className='linkish self-start border-0 border-b bg-transparent p-0 pb-[2px]'
                onClick={(event) => {
                  event.stopPropagation()
                  onOpen(name)
                }}
              >
                Open in playground →
              </button>
            </article>
          )
        })}
      </div>
      <div className='flex flex-col gap-3'>
        <h3 className='h3'>
          Cost for {MIN_BIDDERS} to {MAX_BIDDERS} bidders
        </h3>
        <CostChart profile={profile} levels={levels} bidders={bidders} />
      </div>
    </Section>
  )
}
