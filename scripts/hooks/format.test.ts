// SPDX-License-Identifier: LGPL-3.0-only

import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { test } from 'node:test'

test('shared pre-commit checks staged content and preserves partially staged files', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'interfold-staged-format-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const source = resolve(__dirname, '../..')
  const env = {
    ...process.env,
    PATH: `${source}/node_modules/.bin:${process.env.PATH}`,
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_NOSYSTEM: '1',
  }
  const git = (...args: string[]) => execFileSync('git', args, { cwd: root, env, encoding: 'utf8' })
  git('init', '--quiet')
  git('config', 'user.name', 'Format Test')
  git('config', 'user.email', 'format@example.invalid')
  const config = JSON.parse(readFileSync(join(source, 'package.json'), 'utf8'))['lint-staged']
  writeFileSync(join(root, 'package.json'), JSON.stringify({ private: true, 'lint-staged': config }, null, 2) + '\n')
  const file = join(root, 'partially staged.json')
  writeFileSync(file, '{\n  "value": false\n}\n')
  git('add', '.')
  git('commit', '--quiet', '-m', 'fixture')
  const formatted = '{\n  "value": true\n}\n'
  const unformatted = '{"value":true}\n'
  const hook = () => spawnSync('sh', [join(source, '.husky/pre-commit')], { cwd: root, env, encoding: 'utf8' })
  writeFileSync(file, formatted)
  git('add', 'partially staged.json')
  writeFileSync(file, unformatted)
  const pass = hook()
  assert.equal(pass.status, 0, pass.stdout + pass.stderr)
  assert.equal(git('show', ':partially staged.json'), formatted)
  assert.equal(readFileSync(file, 'utf8'), unformatted)
  git('add', 'partially staged.json')
  writeFileSync(file, formatted)
  assert.notEqual(hook().status, 0)
  assert.equal(git('show', ':partially staged.json'), unformatted)
  assert.equal(readFileSync(file, 'utf8'), formatted)
})
