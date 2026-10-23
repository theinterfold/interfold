// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useMemo, type ReactNode } from 'react'
import { isCorrect, type PublicResult, type RunResult } from '@designs'
import { explanations, priceRuleLabels } from '../lib/designInfo'
import { DesignFacts } from './DesignFacts'
import { LaneView } from './LaneView'
import { GridLegend, VectorGrid } from './VectorGrid'

function Panel({ title, kicker, children }: { title: string; kicker: string; children: ReactNode }) {
  return (
    <div className='card flex flex-col gap-5'>
      <div className='flex flex-col gap-1'>
        <span className='mono-sm text-accent'>{kicker}</span>
        <h3 className='h3'>{title}</h3>
      </div>
      {children}
    </div>
  )
}

function describeResult(result: PublicResult): string {
  const winner = result.winner === null ? 'no single winner' : `bidder ${result.winner}`
  const ties = result.tieSet === undefined ? '' : `, tie set {${result.tieSet.join(', ')}}, random lane ${result.random}`
  return `${winner}, price ${result.price ?? 'not published'}${ties}`
}

/** Everything that one run shows: the explanation, the inputs, the trace, and the output. */
export function Stages({ run }: { run: RunResult }) {
  const { design, setup } = run
  const layout = useMemo(() => design.layout(setup), [design, setup])
  const coefficients = layout.domain === 'coefficients'
  const correct = isCorrect(run)

  return (
    <div className='flex flex-col gap-6'>
      <Panel kicker='About this design' title={design.name}>
        <div className='grid gap-6 md:grid-cols-[1.4fr_1fr]'>
          <div className='prose-ed'>
            <p>{explanations[design.name]}</p>
            <p className='text-[13px] text-ink-soft'>
              <span className='mono-sm'>Reveals · </span>
              {design.disclosure}
            </p>
          </div>
          <DesignFacts design={design} />
        </div>
        {layout.note !== undefined && (
          <div className='note'>
            <span className='mono-sm text-ink-soft'>How to read the grids · </span>
            {layout.note}
          </div>
        )}
        <GridLegend coefficients={coefficients} />
      </Panel>

      <Panel kicker='Step 1' title='Bidder inputs'>
        <p className='m-0 text-[14px] text-ink-soft'>
          Each bidder encrypts {design.inputNames.length} ciphertexts. This simulation shows their plaintext slots. A mask is uniform random
          in every slot, so it is not shown.
        </p>
        {run.inputs.map((plaintexts, bidder) => (
          <details key={bidder} open={bidder === 0} className='border border-rule-strong bg-paper p-4'>
            <summary className='flex flex-wrap items-center gap-3'>
              <span className='font-serif text-[18px]'>Bidder {bidder}</span>
              <span className='tag'>bid {run.bids[bidder]}</span>
              <span className='mono-sm text-ink-soft'>{plaintexts.length} ciphertexts</span>
            </summary>
            <div className='mt-4 flex flex-col gap-6'>
              {plaintexts.map((slots, index) => {
                const name = design.inputNames[index] ?? `input ${index}`
                return (
                  <div key={index} className='flex flex-col gap-2'>
                    <span className='mono-sm'>
                      Ciphertext {index + 1} · <span className='normal-case tracking-normal'>{name}</span>
                    </span>
                    {name.startsWith('mask') ? (
                      <div className='text-[13px] text-ink-soft'>Uniform random values in every slot. Not shown.</div>
                    ) : (
                      <VectorGrid setup={setup} layout={layout} slots={slots} />
                    )}
                  </div>
                )
              })}
            </div>
          </details>
        ))}
      </Panel>

      <Panel kicker='Step 2' title='Program trace'>
        <p className='m-0 text-[14px] text-ink-soft'>
          The program works on the sum of the inputs of all bidders. The badge is the multiplicative depth after the step.
        </p>
        <ol className='m-0 flex list-none flex-col gap-4 p-0'>
          {(run.trace ?? []).map((step, index) => (
            <li key={index}>
              <details open className='border border-rule-strong bg-paper p-4'>
                <summary className='flex flex-wrap items-center gap-3'>
                  <span className='pin'>{index + 1}</span>
                  <span className='font-mono text-[13px]'>{step.label}</span>
                  <span className={`tag ${step.depth === 0 ? 'muted' : 'wait'}`}>depth {step.depth}</span>
                </summary>
                <div className='mt-4'>
                  <VectorGrid setup={setup} layout={layout} slots={step.slots} />
                </div>
              </details>
            </li>
          ))}
        </ol>
      </Panel>

      <Panel kicker='Step 3' title='Output and readout'>
        <VectorGrid setup={setup} layout={layout} slots={run.outputSlots} />
        {design.readLanes !== undefined && <LaneView run={run} />}
        <div className='note ok'>
          <span className='mono-sm text-ink-soft'>Readout · </span>
          {design.readout}.
        </div>
        <div className='overflow-x-auto'>
          <table className='tbl'>
            <thead>
              <tr>
                <th />
                <th>Winner</th>
                <th>{priceRuleLabels[design.priceRule]}</th>
                {design.randomLane && <th>Tie set</th>}
                {design.randomLane && <th>Random lane</th>}
              </tr>
            </thead>
            <tbody>
              <tr>
                <td className='mono-sm'>Decoded from the output</td>
                <td>{run.result.winner === null ? 'none named' : `bidder ${run.result.winner}`}</td>
                <td>{run.result.price ?? '—'}</td>
                {design.randomLane && <td>{`{${(run.result.tieSet ?? []).join(', ')}}`}</td>}
                {design.randomLane && <td>{run.result.random}</td>}
              </tr>
              <tr>
                <td className='mono-sm'>Plaintext expectation</td>
                <td>{run.expected.winner === null ? 'none' : `bidder ${run.expected.winner}`}</td>
                <td>{run.expected.price ?? '—'}</td>
                {design.randomLane && <td>{`{${(run.expected.tieSet ?? []).join(', ')}}`}</td>}
                {design.randomLane && <td>{run.expected.random}</td>}
              </tr>
            </tbody>
          </table>
        </div>
        {run.ownRanks !== null && (
          <div className='flex flex-col gap-2'>
            <span className='mono-sm'>Own rank, read by each bidder with its secret</span>
            <div className='overflow-x-auto'>
              <table className='tbl'>
                <thead>
                  <tr>
                    <th>Bidder</th>
                    <th className='num'>Bid</th>
                    <th className='num'>Rank read</th>
                    <th className='num'>Expected</th>
                  </tr>
                </thead>
                <tbody>
                  {run.ownRanks.map((rank, bidder) => (
                    <tr key={bidder}>
                      <td>{bidder}</td>
                      <td className='num'>{run.bids[bidder]}</td>
                      <td className='num'>{rank ?? '—'}</td>
                      <td className='num'>{run.expectedRanks[bidder]}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
        <div className={`note ${correct ? 'ok' : 'bad'}`} data-testid='correctness'>
          {correct ? '✓ Correct' : '✗ Incorrect'}: the output gives {describeResult(run.result)}. The plain rule on the bids gives{' '}
          {describeResult(run.expected)}.
        </div>
      </Panel>
    </div>
  )
}
