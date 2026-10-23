// SPDX-License-Identifier: LGPL-3.0-only

import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { test } from 'node:test'

test('OpenVM dispatcher retains workspace ownership, arguments, target override and exit status', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'interfold-openvm-dispatch-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const root = fileURLToPath(new URL('../../', import.meta.url))
  writeFileSync(
    join(dir, 'cargo'),
    '#!/usr/bin/env node\nconsole.log(JSON.stringify({ args: process.argv.slice(2), target: process.env.CARGO_TARGET_DIR }))\nprocess.exit(Number(process.env.TEST_STATUS || 0))\n',
    { mode: 0o755 },
  )
  const run = (task, args = [], status = '0') =>
    spawnSync('bash', [fileURLToPath(new URL('./run.sh', import.meta.url)), task, ...args], {
      cwd: dir,
      encoding: 'utf8',
      env: { ...process.env, PATH: `${dir}:${process.env.PATH}`, CARGO_TARGET_DIR: join(dir, 'target override'), TEST_STATUS: status },
    })
  for (const [task, manifest] of [
    ['cli-build', 'Cargo.toml'],
    ['prover-check', 'crates/openvm-prover/Cargo.toml'],
  ]) {
    const result = run(task, ['argument with spaces'])
    assert.equal(result.status, 0, result.stderr)
    const { args, target } = JSON.parse(result.stdout)
    assert.equal(args[args.indexOf('--manifest-path') + 1], join(root, manifest))
    assert.equal(args.at(-1), 'argument with spaces')
    assert.equal(target, join(dir, 'target override'))
  }
  assert.equal(run('cli-build', [], '17').status, 17)
  assert.equal(run('no-such-task').status, 2)
})
