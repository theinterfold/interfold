// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Copies the compiled circuits and the VK anchor into `circuits/` of this package. The circuits are
// build outputs of `circuits/compile.sh` (they are not committed), so the package takes them at
// build time. `src/prover.ts` imports them and `package.json` ships them.
import { copyFileSync, existsSync, mkdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
const circuits = join(packageRoot, '..', 'circuits')
const out = join(packageRoot, 'circuits')

const files = [
  ['lanes/target/negotiation_offer_lanes.json', 'negotiation_offer_lanes.json'],
  ['offer/target/negotiation_offer.json', 'negotiation_offer.json'],
  ['target/vk_anchor.json', 'vk_anchor.json'],
]

const missing = files.map(([from]) => join(circuits, from)).filter((path) => !existsSync(path))
if (missing.length > 0) {
  console.error(`missing build outputs:\n  ${missing.join('\n  ')}\nrun \`bash circuits/compile.sh\` in examples/negotiation first`)
  process.exit(1)
}

mkdirSync(out, { recursive: true })
for (const [from, to] of files) copyFileSync(join(circuits, from), join(out, to))
console.log(`copied ${files.length} circuit files to ${out}`)
