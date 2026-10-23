// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { designNames, designs } from '@designs'
import { drawTiePriority, simulate } from '../lib/simulate'
import { toScenario, type Params } from '../lib/params'
import { Controls } from './Controls'
import { ErrorNote } from './ErrorNote'
import { Section } from './Section'
import { Stages } from './Stages'

interface PlaygroundProps {
  params: Params
  design: string
  onChange: (patch: Partial<Params>) => void
  onDesign: (design: string) => void
}

export function Playground({ params, design, onChange, onDesign }: PlaygroundProps) {
  const scenario = toScenario(params)
  const tiePriority = designs[design].randomTieOrder ? drawTiePriority(params.bidders, params.tieSeed) : null
  const outcome = simulate(design, scenario, true)

  return (
    <Section
      id='playground'
      kicker='02 · Playground'
      title='Run a design on your bids'
      intro='Change the bids, the number of bidders, or the seed. The page runs the simulation again and shows each step: what the bidders send, what the program computes, and what the output reveals.'
    >
      <Controls params={params} tiePriority={tiePriority} onChange={onChange} />
      <div className='tabs' role='tablist' aria-label='Design'>
        {designNames.map((name) => (
          <button key={name} type='button' role='tab' className='tab' aria-selected={name === design} onClick={() => onDesign(name)}>
            {name}
          </button>
        ))}
      </div>
      {outcome.ok ? (
        <Stages run={outcome.run} />
      ) : (
        <ErrorNote error={outcome.error} design={design} profile={params.profile} levels={params.levels} />
      )}
    </Section>
  )
}
