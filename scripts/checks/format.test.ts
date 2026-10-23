// SPDX-License-Identifier: LGPL-3.0-only

import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { test } from 'node:test'

test('CI format check uses base/head diff, preserves paths with spaces and leaves the index untouched', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'interfold-changed-format-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const source = resolve(__dirname, '../..')
  const env = {
    ...process.env,
    PATH: `${source}/node_modules/.bin:${process.env.PATH}`,
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_NOSYSTEM: '1',
  }
  const git = (...args: string[]) => execFileSync('git', args, { cwd: root, env, encoding: 'utf8' }).trim()
  git('init', '--quiet')
  git('config', 'user.name', 'Format Test')
  git('config', 'user.email', 'format@example.invalid')
  writeFileSync(join(root, 'package.json'), '{"private":true}\n') // legacy file outside the diff
  writeFileSync(join(root, 'legacy.json'), '{"unchanged":true}\n')
  git('add', '.')
  git('commit', '--quiet', '-m', 'base')
  const base = git('rev-parse', 'HEAD')
  const file = join(root, 'changed with spaces.json')
  writeFileSync(file, '{\n  "value": true\n}\n')
  git('add', '.')
  git('commit', '--quiet', '-m', 'formatted change')
  const check = () =>
    spawnSync(process.execPath, [join(source, 'scripts/checks/changed-format.mjs'), base, git('rev-parse', 'HEAD')], {
      cwd: root,
      env,
      encoding: 'utf8',
    })
  const pass = check()
  assert.equal(pass.status, 0, pass.stdout + pass.stderr)
  writeFileSync(file, '{"value":false}\n')
  git('add', '.')
  git('commit', '--quiet', '-m', 'unformatted change')
  const before = git('status', '--porcelain=v1')
  assert.notEqual(check().status, 0)
  assert.equal(git('status', '--porcelain=v1'), before)
})
