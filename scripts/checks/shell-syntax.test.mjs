// SPDX-License-Identifier: LGPL-3.0-only

import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

test('shell syntax check parses every argument, including a malformed second script', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'interfold-shell-check-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const first = join(root, 'first.sh')
  const second = join(root, 'second with spaces.sh')
  writeFileSync(first, '#!/bin/bash\necho ok\n')
  writeFileSync(second, '#!/bin/bash\nif true; then\n')
  const run = () =>
    spawnSync(process.execPath, [new URL('./shell-syntax.mjs', import.meta.url).pathname, first, second], { encoding: 'utf8' })
  assert.equal(run().status, 1)
  writeFileSync(second, '#!/bin/bash\necho ok\n')
  assert.equal(run().status, 0)
  writeFileSync(second, '#!/bin/sh\nif true; then\n')
  assert.equal(run().status, 1)
})
