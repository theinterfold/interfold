// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Writes `sdk/test-vectors/slots.json`: published plaintexts (128 u64 LE coefficients) and their 128
// SIMD slots. The slots come from `decodePlaintextSlots` of `@interfold/sdk`, which is the fhe.rs
// `simd_decode` compiled to WebAssembly. The Solidity decoder (`SlotCodec.sol`) and the TypeScript
// codec of `test/helpers.ts` must give the same slots. Run: `pnpm exec tsx scripts/gen-slot-vectors.ts`.

import { writeFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { decodeOutputSlots, Outcome, outputSlotsFor, PRESET, VERSION_BASE } from '../sdk/src/layout'
import { N, POINTS, T, coefficientsToPlaintext, plaintextOf, rng } from '../test/helpers'

const OUT = path.join(path.dirname(fileURLToPath(import.meta.url)), '../sdk/test-vectors/slots.json')

interface Vector {
  name: string
  plaintext: string
  slots: number[]
}

async function vector(name: string, coefficients: readonly number[]): Promise<Vector> {
  const plaintext = coefficientsToPlaintext(coefficients)
  const slots = (await decodeOutputSlots(plaintext)).map(Number)
  return { name, plaintext, slots }
}

const cases: Vector[] = []
cases.push(await vector('zero', new Array<number>(N).fill(0)))
cases.push(await vector('constant term only (every slot is 5)', [5, ...new Array<number>(N - 1).fill(0)]))
cases.push(await vector('x (the evaluation points)', [0, 1, ...new Array<number>(N - 2).fill(0)]))
cases.push(await vector('top coefficient', [...new Array<number>(N - 1).fill(0), 1]))
cases.push(await vector('all 256', new Array<number>(N).fill(T - 1)))
const random = rng(20240601)
for (let i = 0; i < 4; i++) {
  cases.push(
    await vector(
      `pseudo-random ${i}`,
      Array.from({ length: N }, () => random.int(0, T - 1)),
    ),
  )
}

// Outputs of a private round: lanes, gate lane and version slots.
const params = { levels: 6, reserveStep: 1, lots: 3, minLots: 2 }
const versions = [1, 2, 1, 3, 1, 0, 0, 0, 0, 0, 0, 0, 0]
for (const [name, slots] of [
  ['round output: not met', outputSlotsFor(params, versions, Outcome.NotMet)],
  ['round output: undersubscribed', outputSlotsFor(params, versions, Outcome.Undersubscribed)],
  ['round output: sold out at step 3', outputSlotsFor(params, versions, Outcome.SoldOut, 3)],
] as const) {
  const published = plaintextOf(slots)
  const decoded = (await decodeOutputSlots(published)).map(Number)
  if (decoded.join() !== slots.map(Number).join()) throw new Error(`${name}: the fhe.rs decoder disagrees with the TypeScript codec`)
  cases.push({ name, plaintext: published, slots: decoded })
}
if (VERSION_BASE !== 115 || POINTS.length !== N) throw new Error('the layout constants changed')

const file = {
  description:
    'Decoded plaintext of the insecure-simd preset (N = 128, t = 257): the published plaintext (128 u64 LE coefficients) and its 128 SIMD slots, from simd_decode of crates/wasm (decodePlaintextSlots). Written by scripts/gen-slot-vectors.ts.',
  preset: PRESET,
  cases,
}
writeFileSync(OUT, `${JSON.stringify(file, null, 2)}\n`)
console.log(`wrote ${cases.length} cases to ${OUT}`)
