// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import type { Cell } from '@/utils/explainer-example'

export interface SlotRow {
  key: string
  name: React.ReactNode
  /** Whether this row is the winner: its name turns green. */
  winner?: boolean
  /** One cell for each price step. */
  cells: readonly Cell[]
}

interface SlotPictureProps {
  /** One label for each price step, above the columns. */
  axis: readonly string[]
  /** The tooltip of each axis label, if it has more to say than the label. */
  axisTitles?: readonly string[]
  rows: readonly SlotRow[]
  /** The index of the price step to outline, or `null` if the picture shows none. */
  priceStep: number | null
  /** What the reading cell is, in a few words: "the winner’s 1 at the price". */
  reading: string
  /** What the picture shows, for a screen reader. */
  summary: string
}

/** A grid of slots: one row for each bidder and one column for each price step, with the legend under it. */
export const SlotPicture: React.FC<SlotPictureProps> = ({ axis, axisTitles, rows, priceStep, reading, summary }) => {
  const columns = { gridTemplateColumns: `max-content repeat(${axis.length}, minmax(0, 1fr))` }
  return (
    <div className='space-y-3'>
      <div className='overflow-x-auto pb-2'>
        <div className='slots' style={columns} role='group' aria-label={summary}>
          <span />
          {axis.map((label, step) => (
            <span key={step} className='axis' title={axisTitles?.[step]}>
              {label}
            </span>
          ))}
          {rows.map((row) => (
            <React.Fragment key={row.key}>
              <span className={`row-name ${row.winner ? 'font-semibold text-brand-green' : ''}`}>{row.name}</span>
              {row.cells.map((cell, step) => (
                <span
                  key={step}
                  className={`cell ${cell} ${step === priceStep ? 'col-price' : ''}`}
                  title={`step ${step}: ${cell === 'read' ? reading : cell === 'rand' ? 'random number' : 'zero'}`}
                />
              ))}
            </React.Fragment>
          ))}
        </div>
      </div>
      <div className='legend'>
        <span>
          <i className='slots-swatch rand' /> Random number
        </span>
        <span>
          <i style={{ background: 'var(--paper)' }} /> Zero
        </span>
        <span>
          <i style={{ background: 'var(--vote-action)', borderColor: 'var(--vote-action)' }} /> The reading: {reading}
        </span>
        <span>
          <i style={{ boxShadow: '0 0 0 2px var(--ink)' }} /> Price step
        </span>
      </div>
    </div>
  )
}
