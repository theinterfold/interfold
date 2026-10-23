// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * Splits a slot vector by the regions of a design layout, the way `ts/src/trace.ts` prints it. A
 * coefficient design shows signed coefficients (`-1` for `t - 1`).
 */

import type { Layout, Setup, Slots } from '@designs'

/** How many values outside the regions to list before the view only counts them. */
export const OUTSIDE_LIMIT = 12

export interface GridRow {
  name: string
  /** Index of the first value of this row in the vector. */
  start: number
  length: number
}

/** One table: rows of values under one column header. */
export interface GridBlock {
  title: string | null
  /** The label of the corner cell: what the columns count. */
  corner: string
  columns: number
  rows: GridRow[]
}

export interface VectorView {
  /** The values that the grid shows: slots, or signed coefficients. */
  values: number[]
  blocks: GridBlock[]
  points: { name: string; index: number; value: number }[]
  unit: 'slots' | 'coefficients'
  /** What lies outside the regions and the points. */
  outside: { size: number; nonZero: number; listed: { index: number; value: number }[] }
}

export function describeVector(setup: Setup, layout: Layout, slots: Slots): VectorView {
  const { t, degree } = setup.ring
  const signed = layout.domain === 'coefficients'
  const raw = signed ? setup.ring.toCoefficients(slots) : slots
  const values = signed ? raw.map((value) => (value > t / 2 ? value - t : value)) : raw

  const blocks: GridBlock[] = []
  for (const region of layout.regions) {
    if (region.width === undefined) {
      // Regions without a width share one table, as the CLI prints one header for all of them.
      const last = blocks[blocks.length - 1]
      const row: GridRow = { name: region.name, start: region.start, length: region.length }
      if (last !== undefined && last.title === null) {
        last.rows.push(row)
        last.columns = Math.max(last.columns, region.length)
      } else {
        blocks.push({ title: null, corner: layout.columnName ?? 'level p', columns: region.length, rows: [row] })
      }
    } else {
      const rows: GridRow[] = []
      for (let offset = 0; offset < region.length; offset += region.width) {
        rows.push({
          name: String(offset / region.width),
          start: region.start + offset,
          length: Math.min(region.width, region.length - offset),
        })
      }
      blocks.push({ title: region.name, corner: region.rowName ?? 'row', columns: region.width, rows })
    }
  }

  const covered = new Array<boolean>(degree).fill(false)
  for (const region of layout.regions) covered.fill(true, region.start, region.start + region.length)
  for (const point of layout.points ?? []) covered[point.index] = true
  let size = 0
  let nonZero = 0
  const listed: { index: number; value: number }[] = []
  for (let index = 0; index < degree; index++) {
    if (covered[index]) continue
    size++
    if (values[index] === 0) continue
    nonZero++
    if (listed.length < OUTSIDE_LIMIT) listed.push({ index, value: values[index] })
  }

  return {
    values,
    blocks,
    points: (layout.points ?? []).map((point) => ({ name: point.name, index: point.index, value: values[point.index] })),
    unit: signed ? 'coefficients' : 'slots',
    outside: { size, nonZero, listed },
  }
}
