// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { designNames, isCorrect } from '@designs'
import type { Scenario } from '../lib/simulate'
import { simulate } from '../lib/simulate'
import { Section } from './Section'

interface CompareTableProps {
  scenario: Scenario
  selected: string
  onOpen: (design: string) => void
}

/** Every design on the current bids. */
export function CompareTable({ scenario, selected, onOpen }: CompareTableProps) {
  return (
    <Section
      id='compare'
      kicker='03 · All designs on these bids'
      title='Same bids, every design'
      intro={`Bids: ${scenario.bids.join(', ')}. ${scenario.levels} price levels, ${scenario.profile} profile. A design with a random tie priority uses the priority of the playground. The ratio-lane designs pick the winner of a tie with their random lane, which comes from the seed of the masks.`}
    >
      <div className='card flat overflow-x-auto !p-0'>
        <table className='tbl'>
          <thead>
            <tr>
              <th>Design</th>
              <th>Winner</th>
              <th>Price</th>
              <th>Tie set</th>
              <th>Correct</th>
              <th className='num'>ct×ct</th>
              <th className='num'>ct×pt</th>
              <th className='num'>Depth</th>
            </tr>
          </thead>
          <tbody>
            {designNames.map((name) => {
              const outcome = simulate(name, scenario, false)
              const open = (
                <button
                  type='button'
                  className='border-0 bg-transparent p-0 text-left font-mono text-[13px] underline decoration-dotted underline-offset-4'
                  onClick={() => onOpen(name)}
                >
                  {name}
                </button>
              )
              if (!outcome.ok) {
                return (
                  <tr key={name} className={name === selected ? 'current' : undefined}>
                    <td>{open}</td>
                    <td colSpan={7} className='text-danger'>
                      {outcome.error.message}
                    </td>
                  </tr>
                )
              }
              const { run } = outcome
              const correct = isCorrect(run)
              return (
                <tr key={name} className={name === selected ? 'current' : undefined}>
                  <td>{open}</td>
                  <td>{run.result.winner === null ? 'none named' : `bidder ${run.result.winner}`}</td>
                  <td>{run.result.price ?? '—'}</td>
                  <td>{run.result.tieSet === undefined ? '—' : `{${run.result.tieSet.join(', ')}}`}</td>
                  <td className={correct ? 'text-accent' : 'text-danger'} aria-label={correct ? 'correct' : 'incorrect'}>
                    {correct ? '✓' : '✗'}
                  </td>
                  <td className='num'>{run.opCounts.ciphertextProducts}</td>
                  <td className='num'>{run.opCounts.plaintextProducts}</td>
                  <td className='num'>{run.depth}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
      <p className='m-0 text-[12px] text-ink-soft'>
        A dash means that the design publishes no price, or no tie set. A tie goes to the higher index, except in the designs with a random
        tie priority and in the ratio-lane designs, which publish the tie set and pick the winner from it with the random lane.
      </p>
    </Section>
  )
}
