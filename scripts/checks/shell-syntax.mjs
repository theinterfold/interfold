// SPDX-License-Identifier: LGPL-3.0-only

import { execFileSync, spawnSync } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'

// bash -n accepts multiple argv paths but only parses the first script. Invoke it per file.
const files = process.argv.slice(2)
if (!files.length)
  files.push(
    ...execFileSync('git', ['ls-files', '-z', '--cached', '--others', '--exclude-standard', '--', '*.sh', '.husky/*'], { encoding: 'utf8' })
      .split('\0')
      .filter(Boolean),
  )
let failed = false
for (const path of [...new Set(files)].sort()) {
  if (!existsSync(path)) continue
  const firstLine = readFileSync(path, 'utf8').split('\n')[0]
  const shell = /^#!.*(?:\/|\s)sh(?:\s|$)/.test(firstLine) ? 'sh' : 'bash'
  const result = spawnSync(shell, ['-n', path], { stdio: 'inherit' })
  if (result.error) console.error(result.error.message)
  if (result.error || result.status !== 0) failed = true
}
process.exitCode = failed ? 1 : 0
