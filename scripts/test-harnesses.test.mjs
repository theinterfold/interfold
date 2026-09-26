// SPDX-License-Identifier: LGPL-3.0-only

import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

// `docker compose up` can succeed while a scenario container failed, so the runner must check each one.
test('the network runner fails unless every scenario container exited 0', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'interfold-net-runner-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  mkdirSync(join(dir, 'bin'))
  copyFileSync(new URL('../crates/net/tests/run.sh', import.meta.url), join(dir, 'run.sh'))
  writeFileSync(join(dir, 'bin/git'), '#!/bin/sh\necho abcdef0\n', { mode: 0o755 })
  // `compose ps --all --quiet <service>` prints a container ID; `inspect` reports its exit.
  writeFileSync(
    join(dir, 'bin/docker'),
    '#!/bin/sh\ncase "$1 $2" in\n  "compose ps") echo "id-$5" ;;\n  "inspect --format") [ "$4" = "id-$FAILED" ] && echo "exited 17" || echo "exited 0" ;;\nesac\n',
    { mode: 0o755 },
  )
  const run = (failed) =>
    spawnSync('bash', ['run.sh'], {
      cwd: dir,
      env: { ...process.env, PATH: `${dir}/bin:${process.env.PATH}`, FAILED: failed },
      encoding: 'utf8',
    })

  assert.equal(run('').status, 0)
  const result = run('eve')
  assert.equal(result.status, 1)
  assert.match(result.stderr, /Network scenario eve failed/)
})
