// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Prints the exact law of the agreed price and its distance to the ideal one: `pnpm -C sdk uniformity`.
import { buyerPosterior, likelihood, metrics, sellerPosterior } from './uniformity'

const fixed = (value: number, digits = 3) => value.toFixed(digits)

console.log('levels  maxTV  meanTV  worst[s,b]  overweight  underweight  excluded  excess bits')
for (const levels of [2, 3, 4, 8, 11, 12, 16]) {
  const m = metrics(likelihood(levels), levels)
  console.log(
    `${String(levels).padStart(6)}  ${fixed(m.maxTv)}  ${fixed(m.meanTv)}  [${m.worst.s},${m.worst.b}]`.padEnd(40),
    `${fixed(m.overweight, 2).padStart(8)}  ${fixed(m.underweight, 3).padStart(10)}  ${String(m.excluded).padStart(8)}  ${fixed(m.mutualInformation - m.idealMutualInformation, 4)}`,
  )
}

const levels = 16
const table = likelihood(levels)
const [s, b] = [2, 12]
console.log(`\nExact law of the level for s=${s}, b=${b} (n=${b - s + 1}); ideal 1/n = ${fixed(1 / (b - s + 1), 4)} per level:`)
console.log(
  Array.from({ length: levels }, (_, p) => (p >= s && p <= b ? `${p}:${(table[s][b][p] * 16).toFixed(0)}/16` : null))
    .filter(Boolean)
    .join('  '),
)

const p = 7
console.log(`\nAfter the output p=${p}: the seller (s=${s}) learns b >= ${p}; its posterior on b (uniform prior):`)
console.log(
  sellerPosterior(table, levels, s, p)
    .map((v, i) => (v > 0 ? `${i}:${fixed(v, 3)}` : null))
    .filter(Boolean)
    .join('  '),
)
console.log(`the buyer (b=${b}) learns s <= ${p}; its posterior on s (uniform prior):`)
console.log(
  buyerPosterior(table, levels, b, p)
    .map((v, i) => (v > 0 ? `${i}:${fixed(v, 3)}` : null))
    .filter(Boolean)
    .join('  '),
)
