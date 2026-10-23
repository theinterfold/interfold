// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { AnyDesign } from '@designs'
import { priceRuleLabels, tieRuleLabels } from '../lib/designInfo'

/** What a design reveals and how it decides: the facts that do not depend on the bids. */
export function DesignFacts({ design }: { design: AnyDesign }) {
  const facts: [string, string][] = [
    ['Price', priceRuleLabels[design.priceRule]],
    ['Ties', design.randomLane ? tieRuleLabels.lane : design.randomTieOrder ? tieRuleLabels.random : tieRuleLabels.index],
    ['Own rank', design.revealsOwnRank ? 'Each bidder can read it' : 'Not readable'],
  ]
  return (
    <dl className='m-0 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-[13px]'>
      {facts.map(([name, value]) => (
        <div key={name} className='contents'>
          <dt className='mono-sm pt-[3px] text-ink-soft'>{name}</dt>
          <dd className='m-0'>{value}</dd>
        </div>
      ))}
    </dl>
  )
}
