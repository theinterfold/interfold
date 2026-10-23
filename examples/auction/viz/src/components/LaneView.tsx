// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useMemo } from 'react'
import { weightBits, type LaneKind, type LaneReadout, type RunResult } from '@designs'

/** The longest value that a cell prints. A longer value shows in the tooltip. */
const CELL_DIGITS = 3

const kindLabels: Record<LaneKind, string> = {
  zero: 'zero',
  random: 'uniform',
  result: 'result',
}

function LaneGrid({ readout, levels }: { readout: LaneReadout; levels: number }) {
  return (
    <div className='scroll-x'>
      <div className='vgrid' style={{ gridTemplateColumns: `max-content repeat(${levels}, 26px)` }}>
        <div className='corner'>lane \ level p</div>
        {Array.from({ length: levels }, (_, level) => (
          <div key={level} className={`axis ${level === readout.price ? 'text-warm' : ''}`}>
            {level}
          </div>
        ))}
        {readout.rows.map((row) => (
          <div key={row.name} className='contents'>
            <div className='row-name'>{row.name}</div>
            {row.kinds.map((kind, level) => {
              const text = String(row.values[level])
              const label = `${row.name}, level ${level}: ${kindLabels[kind]} (${text})`
              if (kind === 'zero') return <div key={level} className='cell zero' title={label} />
              if (kind === 'random') return <div key={level} className='cell rand' title={label} />
              return (
                <div key={level} className='cell result' title={label}>
                  {text.length <= CELL_DIGITS ? text : null}
                </div>
              )
            })}
          </div>
        ))}
      </div>
    </div>
  )
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className='flex flex-col'>
      <span className='mono-sm text-ink-soft'>{label}</span>
      <span className='font-serif text-[22px] leading-none'>{value}</span>
    </div>
  )
}

/** The bidders of one weight group, marked when the group value puts them in the tie set. */
function GroupRow({ readout, group, width }: { readout: LaneReadout; group: number; width: number }) {
  const first = group * width
  const size = readout.groupSizes[group]
  return (
    <tr>
      <td className='mono-sm'>{group}</td>
      <td className='num'>{readout.groupValues[group]}</td>
      <td>
        <span className='flex flex-wrap gap-1'>
          {Array.from({ length: size }, (_, i) => first + i).map((bidder) => (
            <span key={bidder} className={`tag ${readout.tieSet.includes(bidder) ? 'live' : 'muted'}`}>
              {bidder}
            </span>
          ))}
        </span>
      </td>
    </tr>
  )
}

/**
 * The output of a ratio-lane design as lanes: each lane is 0 above the price level, carries the
 * result at it, and is uniform below it. Under the lanes, the tie set, the random lane, and the
 * winner that they give.
 */
export function LaneView({ run }: { run: RunResult }) {
  const { design, setup } = run
  const readout = useMemo(() => design.readLanes!(setup, run.outputSlots), [design, setup, run.outputSlots])
  const second = design.priceRule === 'second'
  const width = weightBits(setup.ring.t)
  const size = readout.tieSet.length

  return (
    <div className='flex flex-col gap-4' data-testid='lane-view'>
      <div className='flex flex-col gap-1'>
        <span className='mono-sm'>Lanes{second ? ` of copy ${readout.copy + 1} of ${readout.copies}` : ''}</span>
        <p className='m-0 text-[13px] text-ink-soft'>
          One row for each lane, one column for each price level.{' '}
          {second ? 'The copy shown is the first copy with y ≠ 0 at the price level. ' : 'Each weight group has one lane. '}
          The price level is the last column that is not zero.
        </p>
      </div>
      <LaneGrid readout={readout} levels={setup.levels} />
      <div className='legend'>
        <span>
          <i className='zero' /> 0 (above the price level)
        </span>
        <span>
          <i className='result' /> the result lane at the price level
        </span>
        <span>
          <i className='rand' /> uniform value (below the price level)
        </span>
      </div>

      <div className='flex flex-wrap gap-x-10 gap-y-3'>
        <Stat label='Price level' value={readout.price === null ? '—' : String(readout.price)} />
        <Stat label='Tie set' value={size === 0 ? '—' : `{${readout.tieSet.join(', ')}}`} />
        <Stat label='Random lane' value={String(readout.random)} />
        <Stat label='Winner' value={readout.winner === null ? '—' : `bidder ${readout.winner}`} />
      </div>

      <div className='flex flex-col gap-2'>
        <span className='mono-sm'>Weight groups: the value at the price level names the tie set</span>
        <div className='overflow-x-auto'>
          <table className='tbl'>
            <thead>
              <tr>
                <th>Group</th>
                <th className='num'>{second ? 'Ratio z / y' : 'Lane value'}</th>
                <th>Bidders (marked: in the tie set)</th>
              </tr>
            </thead>
            <tbody>
              {readout.groupValues.map((_, group) => (
                <GroupRow key={group} readout={readout} group={group} width={width} />
              ))}
            </tbody>
          </table>
        </div>
        <p className='m-0 text-[12px] text-ink-soft'>
          Bidder k has the weight 2^(k mod {width}) in group ⌊k / {width}⌋. Bit i of the value of group γ is set when bidder γ · {width} + i
          is in the set.
        </p>
      </div>

      {readout.winner === null ? (
        <div className='note bad'>
          The output does not name a tie set: no lane is set, the copies disagree, or a value names a bidder that does not exist.
        </div>
      ) : (
        <div className='note ok' data-testid='tie-resolution'>
          <span className='mono-sm text-ink-soft'>Tie resolution · </span>
          {size === 1
            ? `One bidder is in the set, so bidder ${readout.winner} wins. The random lane does not matter.`
            : `The set has ${size} bidders. The random lane is ${readout.random}, and ${readout.random} mod ${size} = ${readout.random % size}. The winner is entry ${readout.random % size} of the sorted set: bidder ${readout.winner}.`}
          {second &&
            ` ${readout.copiesAgree ? 'All copies that fixed the price give the same ratios.' : 'The copies that fixed the price disagree.'}`}
        </div>
      )}
    </div>
  )
}
