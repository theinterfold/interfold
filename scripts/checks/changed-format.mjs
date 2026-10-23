// SPDX-License-Identifier: LGPL-3.0-only

import { execFileSync } from 'node:child_process'
import { existsSync } from 'node:fs'

const [base, head] = process.argv.slice(2)
if (!base || !head || process.argv.length !== 4) throw new Error('Usage: node scripts/checks/changed-format.mjs <base-sha> <head-sha>')
// Resolve to immutable commits first; argv and NUL separators preserve unusual filenames.
const commit = (ref) => execFileSync('git', ['rev-parse', '--verify', `${ref}^{commit}`], { encoding: 'utf8' }).trim()
const files = execFileSync('git', ['diff', '--name-only', '-z', '--diff-filter=ACMR', `${commit(base)}...${commit(head)}`, '--'], {
  encoding: 'utf8',
})
  .split('\0')
  .filter((path) => /\.(js|jsx|mjs|cjs|json|md|mdx|ts|tsx|yml|yaml|css|sol)$/.test(path) && existsSync(path))
// Bound argv size without shell interpolation. --check never formats or stages files in CI.
for (let i = 0; i < files.length; i += 100)
  execFileSync('pnpm', ['exec', 'prettier', '--check', '--', ...files.slice(i, i + 100)], { stdio: 'inherit' })
