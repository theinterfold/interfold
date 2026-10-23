// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { memo, useMemo } from 'react'
import type { Layout, Setup, Slots } from '@designs'
import { OUTSIDE_LIMIT, describeVector, type GridBlock } from '../lib/vector'

/** The longest value that a cell prints. A longer value is hatched, and the tooltip has it. */
const CELL_DIGITS = 3

interface VectorGridProps {
  setup: Setup
  layout: Layout
  slots: Slots
}

function Block({ block, values }: { block: GridBlock; values: number[] }) {
  return (
    <div>
      {block.title !== null && <div className='mono-sm mb-2 text-ink-soft'>{block.title}</div>}
      <div className='scroll-x'>
        <div className='vgrid' style={{ gridTemplateColumns: `max-content repeat(${block.columns}, 26px)` }}>
          <div className='corner'>{block.corner}</div>
          {Array.from({ length: block.columns }, (_, column) => (
            <div key={column} className='axis'>
              {column}
            </div>
          ))}
          {block.rows.map((row) => (
            <RowCells key={row.name} row={row} columns={block.columns} values={values} />
          ))}
        </div>
      </div>
    </div>
  )
}

function RowCells({ row, columns, values }: { row: GridBlock['rows'][number]; columns: number; values: number[] }) {
  return (
    <>
      <div className='row-name'>{row.name}</div>
      {Array.from({ length: columns }, (_, column) => {
        if (column >= row.length) return <div key={column} />
        const index = row.start + column
        const value = values[index]
        if (value === 0) return <div key={column} className='cell zero' title={`[${index}] = 0`} />
        const text = String(value)
        const short = text.length <= CELL_DIGITS
        return (
          <div key={column} className={short ? 'cell small' : 'cell rand'} title={`[${index}] = ${text}`}>
            {short ? text : null}
          </div>
        )
      })}
    </>
  )
}

/**
 * One slot vector, cut by the regions of the design layout. A zero is a filled cell. A non-zero
 * value is muted: short values are printed, long (random) values are hatched and show in the tooltip.
 */
export const VectorGrid = memo(function VectorGrid({ setup, layout, slots }: VectorGridProps) {
  const view = useMemo(() => describeVector(setup, layout, slots), [setup, layout, slots])
  const { outside } = view
  return (
    <div className='flex flex-col gap-4'>
      {view.blocks.map((block, index) => (
        <Block key={index} block={block} values={view.values} />
      ))}
      {view.points.length > 0 && (
        <div className='flex flex-wrap items-center gap-2 text-[12px]'>
          <span className='mono-sm text-ink-soft'>At the score positions</span>
          {view.points.map((point) => (
            <span key={point.name} className={`tag ${point.value === 0 ? 'live' : 'muted'}`} title={`[${point.index}]`}>
              {point.name} = {point.value}
            </span>
          ))}
        </div>
      )}
      <div className='text-[12px] text-ink-soft'>
        {outside.nonZero === 0 && outside.size > 0 && `${outside.size} ${view.unit} not shown: all 0.`}
        {outside.nonZero > 0 &&
          outside.nonZero <= OUTSIDE_LIMIT &&
          `Also non-zero outside the regions: ${outside.listed.map((entry) => `[${entry.index}] = ${entry.value}`).join(', ')}.`}
        {outside.nonZero > OUTSIDE_LIMIT && `${outside.size} ${view.unit} not shown: ${outside.nonZero} non-zero.`}
      </div>
    </div>
  )
})

export function GridLegend({ coefficients }: { coefficients: boolean }) {
  return (
    <div className='legend'>
      <span>
        <i className='zero' /> 0 (the zero pattern carries the result)
      </span>
      <span>
        <i className='small' /> small value
      </span>
      <span>
        <i className='rand' /> large or random value (hover for the number)
      </span>
      <span>{coefficients ? 'Coefficients, signed: -1 means t - 1.' : 'Slots, mod t.'}</span>
    </div>
  )
}
