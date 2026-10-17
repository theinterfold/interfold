// SPDX-License-Identifier: LGPL-3.0-only

import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const run = (args) => execFileSync('pnpm', args, { cwd: root, stdio: 'inherit' })

try {
  // The SDK build selects insecure-64. Restore the node pair before compiling its contracts.
  const { preset, committee } = JSON.parse(readFileSync(join(root, 'circuits/bin/.active-preset.json'), 'utf8'))
  if (!preset || !committee) throw new Error('Select a complete node artifact pair with pnpm build:circuits first.')
  let buildError
  try {
    run(['wasm:build'])
    run(['-C', 'examples/CRISP', 'build:sdk'])
  } catch (error) {
    buildError = error
  }
  try {
    run(['build:circuits', '--preset', preset, '--committee', committee, '--hydrate-bin-only'])
  } catch (error) {
    throw new AggregateError([buildError, error].filter(Boolean), 'Cannot restore the node artifact pair after CRISP setup.')
  }
  if (buildError) throw buildError
  // CRISP's Hardhat configuration imports the compiled tasks, not the Solidity-only build.
  run(['evm:build'])
} catch (error) {
  console.error(error)
  process.exitCode = 1
}
