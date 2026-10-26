// SPDX-License-Identifier: LGPL-3.0-only

import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

test('integration prebuild selects only the fixture-bin owner and preserves a build failure', (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'interfold-fixture-prebuild-')))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const lib = join(root, 'tests/integration/lib')
  const bin = join(root, 'bin')
  mkdirSync(lib, { recursive: true })
  mkdirSync(bin)
  copyFileSync(new URL('../../tests/integration/lib/prebuild.sh', import.meta.url), join(lib, 'prebuild.sh'))
  const log = join(root, 'cargo.json')
  writeFileSync(
    join(bin, 'cargo'),
    `#!${process.execPath}\nrequire('node:fs').writeFileSync(${JSON.stringify(
      log,
    )}, JSON.stringify({ cwd: process.cwd(), args: process.argv.slice(2) })); process.exit(17)\n`,
  )
  chmodSync(join(bin, 'cargo'), 0o755)
  const result = spawnSync('bash', [join(lib, 'prebuild.sh')], {
    cwd: lib,
    env: { ...process.env, PATH: `${bin}:${process.env.PATH}` },
    encoding: 'utf8',
  })
  assert.equal(result.status, 17, result.stdout + result.stderr)
  const call = JSON.parse(readFileSync(log, 'utf8'))
  assert.equal(call.cwd, root)
  assert.deepEqual(call.args, ['build', '--locked', '-p', 'e3-tests', '--bin', 'fake_encrypt', '--bin', 'pack_e3_params'])
  assert.doesNotMatch(result.stdout, /PREPARING ZK CIRCUITS/)
})
