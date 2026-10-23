// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Copies the compiled bid circuits and the VK anchors into `circuits/` of this package. The circuits
// are build outputs of `scripts/compile_circuits.sh` (they are not committed), so the package takes
// them at build time. `src/prover.ts` imports them and `package.json` ships them.
import { copyFileSync, existsSync, mkdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
const circuits = join(packageRoot, '..', 'circuits')
const out = join(packageRoot, 'circuits')

const files = [
  ['pair/target/auction_bid_pair.json', 'auction_bid_pair.json'],
  ['masks/target/auction_bid_masks.json', 'auction_bid_masks.json'],
  ['bid3/target/auction_bid3.json', 'auction_bid3.json'],
  ['bid4/target/auction_bid4.json', 'auction_bid4.json'],
  ['target/vk_anchor.json', 'vk_anchor.json'],
]

const missing = files.map(([from]) => join(circuits, from)).filter((path) => !existsSync(path))
if (missing.length > 0) {
  console.error(`missing build outputs:\n  ${missing.join('\n  ')}\nrun \`pnpm compile:circuits\` in examples/auction-e2e first`)
  process.exit(1)
}

mkdirSync(out, { recursive: true })
for (const [from, to] of files) copyFileSync(join(circuits, from), join(out, to))
console.log(`copied ${files.length} circuit files to ${out}`)
