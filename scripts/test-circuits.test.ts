// SPDX-License-Identifier: LGPL-3.0-only

import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

for (const recursiveExit of [0, 17]) {
  test(`Noir runner selects both packages and propagates recursive exit ${recursiveExit}`, (t) => {
    const root = mkdtempSync(join(tmpdir(), 'interfold-noir-runner-'))
    t.after(() => rmSync(root, { recursive: true, force: true }))
    const packages = ['circuits/lib', 'circuits/bin/recursive_aggregation/decryption_aggregator']
    for (const dir of ['scripts', 'fake-bin', ...packages]) mkdirSync(join(root, dir), { recursive: true })
    copyFileSync(join(__dirname, 'test-circuits.sh'), join(root, 'scripts/test-circuits.sh'))
    writeFileSync(
      join(root, 'fake-bin/nargo'),
      `#!/bin/sh
printf '%s\\n' "$PWD" >> "$RUN_LOG"
case "$PWD" in */decryption_aggregator) exit ${recursiveExit} ;; esac
`,
      { mode: 0o755 },
    )
    const log = join(root, 'packages.log')
    const result = spawnSync('bash', [join(root, 'scripts/test-circuits.sh')], {
      cwd: root,
      env: { ...process.env, PATH: `${join(root, 'fake-bin')}:${process.env.PATH}`, RUN_LOG: log },
      encoding: 'utf8',
      timeout: 5_000,
    })
    assert.equal(result.status, recursiveExit, result.stderr)
    assert.deepEqual(
      readFileSync(log, 'utf8').trim().split('\n'),
      packages.map((dir) => join(root, dir)),
    )
    if (recursiveExit) assert.doesNotMatch(result.stdout, /tests passed/)
  })
}
