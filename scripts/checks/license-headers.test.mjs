// SPDX-License-Identifier: LGPL-3.0-only

import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

test('license fix retains executable shebang and mode, and never rewrites another SPDX license', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'interfold-license-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const script = join(root, 'executable.ts')
  const alternate = join(root, 'alternate.ts')
  writeFileSync(script, '#!/usr/bin/env tsx\nconsole.log("ok")\n', { mode: 0o755 })
  const original = '// SPDX-License-Identifier: Apache-2.0\nconst value = 1\n'
  writeFileSync(alternate, original)
  const run = (...args) =>
    spawnSync('bash', [new URL('./license-headers.sh', import.meta.url).pathname, ...args], {
      env: { ...process.env, TEST_FILES: `${script}\n${alternate}` },
      encoding: 'utf8',
    })
  assert.equal(run('--check-only').status, 1)
  assert.equal(run('--fix').status, 0)
  assert.match(readFileSync(script, 'utf8'), /^#!\/usr\/bin\/env tsx\n\/\/ SPDX-License-Identifier: LGPL-3.0-only\n/)
  assert.equal(statSync(script).mode & 0o777, 0o755)
  assert.equal(readFileSync(alternate, 'utf8'), original)
  assert.equal(run('--check-only').status, 0)
  const fixed = readFileSync(script, 'utf8')
  assert.equal(run('--fix').status, 0)
  assert.equal(readFileSync(script, 'utf8'), fixed)
})
