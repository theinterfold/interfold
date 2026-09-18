// SPDX-License-Identifier: LGPL-3.0-only

import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('../', import.meta.url))
const destination = path.join(root, 'target/crisp-prover/fhe')
const revision = 'f2c1d2258fbeef6dbdf5ade68438203fd80a648e'
const patch = path.join(root, 'examples/CRISP/prover/patches/fhe-lazy-multiplication.patch')
function git(args, cwd = destination) {
  const result = spawnSync('git', args, { cwd, encoding: 'utf8' })
  if (result.error || result.status !== 0) throw result.error ?? new Error(result.stderr)
  return result.stdout.trimEnd()
}
if (!existsSync(destination)) {
  mkdirSync(path.dirname(destination), { recursive: true })
  git(['clone', '--filter=blob:none', '--no-checkout', 'https://github.com/gnosisguild/fhe.rs.git', destination], root)
  git(['checkout', '--detach', revision])
}
if (git(['rev-parse', 'HEAD']) !== revision) throw new Error(`The FHE checkout must use revision ${revision}`)
const expected = readFileSync(patch, 'utf8').trimEnd()
const actual = git(['diff', 'HEAD'])
if (actual && actual !== expected) throw new Error('The FHE checkout contains changes that differ from the experiment patch')
if (!actual) {
  git(['apply', '--check', patch])
  git(['apply', patch])
}
if (git(['diff', 'HEAD']) !== expected) throw new Error('The applied FHE patch does not match the experiment')
console.log(`FHE ${revision}: experiment patch verified`)
