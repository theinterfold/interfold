// SPDX-License-Identifier: LGPL-3.0-only

import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test, { type TestContext } from 'node:test'

function fixture(t: TestContext, circuits: string[]) {
  const root = mkdtempSync(join(tmpdir(), 'interfold-verifier-selection-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const write = (file: string, value: string, mode?: number) => {
    const target = join(root, file)
    mkdirSync(dirname(target), { recursive: true })
    writeFileSync(target, value, { mode })
  }
  write('package.json', '{"private":true,"type":"commonjs"}')
  write('dist/circuits/insecure-512/minimum/.build-stamp.json', JSON.stringify({ preset: 'insecure-512', committee: 'minimum' }))
  write('circuits/bin/.active-preset.json', JSON.stringify({ preset: 'insecure-512', committee: 'minimum' }))
  mkdirSync(join(root, 'scripts'))
  for (const name of ['generate-verifiers.ts', 'circuit-constants.ts']) copyFileSync(join(__dirname, name), join(root, 'scripts', name))
  for (const circuit of circuits)
    write(`circuits/bin/recursive_aggregation/${circuit}/Nargo.toml`, `[package]\nname = "${circuit}"\ntype = "bin"\n`)
  // Stand in only for external version checks. Discovery and CLI control flow remain unchanged.
  for (const tool of ['nargo', 'bb']) write(`bin/${tool}`, '#!/bin/sh\nprintf "fixture tool\\n"\n', 0o755)
  return (args: string[]) => {
    const result = spawnSync('pnpm', ['exec', 'tsx', join(root, 'scripts/generate-verifiers.ts'), ...args], {
      cwd: join(__dirname, '..'),
      env: { ...process.env, PATH: `${join(root, 'bin')}:${process.env.PATH}` },
      encoding: 'utf8',
      timeout: 15_000,
    })
    assert.equal(result.signal, null, result.error?.message)
    assert.equal(existsSync(join(root, 'packages')), false, 'Selection checks must not create committed verifier output')
    return { status: result.status, output: result.stdout + result.stderr }
  }
}

test('check mode rejects an empty circuit tree', (t) => {
  const result = fixture(t, [])(['--check', '--no-compile'])
  assert.equal(result.status, 1, result.output)
  assert.match(result.output, /No circuits found/)
})

test('check mode rejects a wholly missing requested circuit', (t) => {
  const result = fixture(t, ['dkg_aggregator'])(['--check', '--no-compile', '--circuits', 'decryption_aggregator'])
  assert.equal(result.status, 1, result.output)
  assert.match(result.output, /Cannot find requested circuits: decryption_aggregator/)
})

test('check mode rejects a partially present selection before generation', (t) => {
  const result = fixture(t, ['dkg_aggregator'])(['--check', '--no-compile', '--circuits', 'dkg_aggregator,decryption_aggregator'])
  assert.equal(result.status, 1, result.output)
  assert.match(result.output, /Cannot find requested circuits: decryption_aggregator/)
  assert.doesNotMatch(result.output, /requires the committed verifier directory/)
})

test('a group filter cannot silently drop a requested circuit', (t) => {
  const result = fixture(t, ['dkg_aggregator'])(['--dry-run', '--group', 'threshold', '--circuits', 'dkg_aggregator'])
  assert.equal(result.status, 1, result.output)
  assert.match(result.output, /Cannot find requested circuits: dkg_aggregator/)
})

test('a complete explicit selection reaches the dry-run output', (t) => {
  const result = fixture(t, ['dkg_aggregator', 'decryption_aggregator'])([
    '--dry-run',
    '--circuits',
    'dkg_aggregator,decryption_aggregator',
  ])
  assert.equal(result.status, 0, result.output)
  assert.match(result.output, /Found 2 circuit\(s\)/)
  assert.match(
    result.output,
    /Would generate verifiers for:.*recursive_aggregation\/decryption_aggregator.*recursive_aggregation\/dkg_aggregator/,
  )
})

test('default discovery retains all available circuits', (t) => {
  const result = fixture(t, ['dkg_aggregator', 'decryption_aggregator'])(['--dry-run'])
  assert.equal(result.status, 0, result.output)
  assert.match(result.output, /Found 2 circuit\(s\)/)
})

test('an explicit selection excludes unrelated circuits', (t) => {
  const result = fixture(t, ['dkg_aggregator', 'unselected'])(['--dry-run', '--circuits', 'dkg_aggregator'])
  assert.equal(result.status, 0, result.output)
  assert.match(result.output, /Found 1 circuit\(s\)/)
  assert.doesNotMatch(result.output, /recursive_aggregation\/unselected/)
})
