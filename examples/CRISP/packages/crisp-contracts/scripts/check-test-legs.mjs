// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * Assert every contract test file belongs to exactly one CI leg.
 *
 * The suite is split across `test:unit`, `test:input-tree` and the `test:ballots:*` legs because
 * proving a ballot costs minutes and the legs run in parallel. Naming files explicitly is what
 * makes the split balanced, and it is also how the split breaks: a new test file that no leg names
 * is never run by CI, and nothing reports it. `pnpm test` still runs everything, so the gap only
 * exists in CI, where it looks exactly like a passing build.
 */

import { readFileSync, readdirSync } from 'fs'
import { dirname, join } from 'path'
import { fileURLToPath } from 'url'

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
const LEGS = ['test:unit', 'test:input-tree', 'test:ballots:program', 'test:ballots:census']

const scripts = JSON.parse(readFileSync(join(packageRoot, 'package.json'), 'utf-8')).scripts ?? {}

const legOf = new Map()
for (const leg of LEGS) {
  const command = scripts[leg]
  if (!command) {
    console.error(`✗ package.json has no "${leg}" script, but CI runs it.`)
    process.exit(1)
  }
  for (const file of command.match(/tests\/\S+\.test\.ts/g) ?? []) {
    legOf.set(file, [...(legOf.get(file) ?? []), leg])
  }
}

const onDisk = readdirSync(join(packageRoot, 'tests'))
  .filter((name) => name.endsWith('.test.ts'))
  .map((name) => `tests/${name}`)
  .sort()

const problems = []
for (const file of onDisk) {
  const legs = legOf.get(file)
  if (!legs) problems.push(`${file} is in no leg — CI would never run it. Add it to one of ${LEGS.join(', ')}.`)
  else if (legs.length > 1) problems.push(`${file} is in ${legs.length} legs (${legs.join(', ')}) — it would run twice.`)
}
for (const file of legOf.keys()) {
  if (!onDisk.includes(file)) problems.push(`${file} is named by a leg but does not exist.`)
}

if (problems.length > 0) {
  console.error('✗ contract test legs do not cover the suite:')
  for (const problem of problems) console.error(`    ${problem}`)
  process.exit(1)
}

console.log(`✓ ${onDisk.length} contract test file(s), each in exactly one leg.`)
