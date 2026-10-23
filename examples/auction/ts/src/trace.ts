// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * Prints a slot vector grouped by region and level, for `--trace`. A zero prints as `.`, so the
 * zero pattern that carries the result is easy to see. A coefficient design prints coefficients
 * as signed values (`-1` for `t - 1`).
 */

import type { Layout, Setup } from './designs/design'
import type { RunResult, AnyDesign } from './index'
import type { Slots } from './field'

/** How many values outside the regions to list before the printer only counts them. */
const OUTSIDE_LIMIT = 12

function cell(value: number, t: number, signed: boolean): string {
  if (value === 0) return '.'
  return String(signed && value > t / 2 ? value - t : value)
}

/** The lines that show `slots` by the regions of `layout`. */
export function formatVector(setup: Setup, layout: Layout, slots: Slots): string[] {
  const { t, degree } = setup.ring
  const signed = layout.domain === 'coefficients'
  const values = signed ? setup.ring.toCoefficients(slots) : slots
  const lines: string[] = []
  const covered = new Array<boolean>(degree).fill(false)
  for (const region of layout.regions) {
    for (let p = region.start; p < region.start + region.length; p++) covered[p] = true
  }
  for (const point of layout.points ?? []) covered[point.index] = true
  const shown = layout.regions.flatMap((region) => values.slice(region.start, region.start + region.length))
  const longest = Math.max(1, ...layout.regions.map((region) => region.length))
  const digits = Math.max(String(longest - 1).length, ...shown.map((value) => cell(value, t, signed).length))
  const pad = (text: string) => text.padStart(digits)
  const nameWidth = Math.max(...layout.regions.map((region) => region.name.length), (layout.columnName ?? 'level p').length)

  let headerPrinted = false
  for (const region of layout.regions) {
    const slotsOfRegion = values.slice(region.start, region.start + region.length)
    if (region.width === undefined) {
      if (!headerPrinted) {
        const columns = Array.from({ length: region.length }, (_, p) => pad(String(p))).join(' ')
        lines.push(`    ${(layout.columnName ?? 'level p').padEnd(nameWidth)} ${columns}`)
        headerPrinted = true
      }
      lines.push(`    ${region.name.padEnd(nameWidth)} ${slotsOfRegion.map((v) => pad(cell(v, t, signed))).join(' ')}`)
    } else {
      lines.push(`    ${region.name}`)
      const rows = Math.ceil(region.length / region.width)
      const columns = Array.from({ length: region.width }, (_, c) => pad(String(c))).join(' ')
      lines.push(`      ${(region.rowName ?? 'row').padEnd(8)} ${columns}   <- column`)
      for (let row = 0; row < rows; row++) {
        const rowValues = slotsOfRegion.slice(row * region.width, (row + 1) * region.width)
        lines.push(`      ${String(row).padEnd(8)} ${rowValues.map((v) => pad(cell(v, t, signed))).join(' ')}`)
      }
    }
  }

  if (layout.points !== undefined) {
    const points = layout.points.map((point) => `${point.name} [${point.index}] = ${cell(values[point.index], t, signed)}`)
    lines.push(`    at the score positions: ${points.join(', ')}`)
  }
  const outside: string[] = []
  let outsideNonZero = 0
  for (let p = 0; p < degree; p++) {
    if (covered[p] || values[p] === 0) continue
    outsideNonZero++
    if (outside.length < OUTSIDE_LIMIT) outside.push(`[${p}]=${cell(values[p], t, signed)}`)
  }
  const unit = signed ? 'coefficients' : 'slots'
  const outsideSize = covered.filter((c) => !c).length
  if (outsideNonZero === 0) {
    if (outsideSize > 0) lines.push(`    (${outsideSize} ${unit} not shown: all 0)`)
  } else if (outsideNonZero <= OUTSIDE_LIMIT) {
    lines.push(`    also non-zero outside the regions: ${outside.join(' ')}`)
  } else {
    lines.push(`    (${outsideSize} ${unit} not shown: ${outsideNonZero} non-zero)`)
  }
  return lines
}

/** The full trace of one run: the bidder inputs, then every step that the design shows. */
export function formatTrace(run: RunResult): string[] {
  const { setup, design } = run
  const layout = design.layout(setup)
  const lines: string[] = []
  lines.push(`-- trace: ${design.name} (N=${setup.ring.degree}, t=${setup.ring.t}, ${layout.domain}) --`)
  if (layout.note !== undefined) lines.push(`   ${layout.note}`)
  lines.push('   "." is 0. Every value is mod t.')
  lines.push(...inputLines(setup, layout, design, run))
  for (const step of run.trace ?? []) {
    lines.push('', `  step: ${step.label}  (depth ${step.depth})`)
    lines.push(...formatVector(setup, layout, step.slots))
  }
  lines.push('', `  output slots read as: ${design.readout}`)
  return lines
}

function inputLines(setup: Setup, layout: Layout, design: AnyDesign, run: RunResult): string[] {
  const lines: string[] = ['', '  inputs']
  run.inputs.forEach((plaintexts, bidder) => {
    lines.push(`  bidder ${bidder}, bid ${run.bids[bidder]}`)
    plaintexts.forEach((slots, j) => {
      const name = design.inputNames[j] ?? `input ${j}`
      lines.push(`   ${name}`)
      // A mask is uniform random in every slot: its values do not help to read the tally.
      if (name.startsWith('mask')) {
        lines.push('    (uniform random values, not shown)')
        return
      }
      lines.push(...formatVector(setup, layout, slots))
    })
  })
  return lines
}
