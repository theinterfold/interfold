// SPDX-License-Identifier: LGPL-3.0-only

import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..')

function fixture(t, script) {
  const directory = mkdtempSync(join(tmpdir(), 'interfold-harness-test-'))
  t.after(() => rmSync(directory, { recursive: true, force: true }))
  const executable = join(directory, script)
  const bin = join(directory, 'fake-bin')
  const temporary = join(directory, 'tmp')
  const log = join(directory, 'commands.jsonl')
  for (const path of [dirname(executable), bin, temporary]) mkdirSync(path, { recursive: true })
  copyFileSync(join(repo, script), executable)
  writeFileSync(log, '')
  return {
    directory,
    temporary,
    write(relative, code) {
      const path = join(directory, relative)
      mkdirSync(dirname(path), { recursive: true })
      writeFileSync(path, `#!${process.execPath}\n${code}\n`, { mode: 0o755 })
    },
    calls() {
      return readFileSync(log, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse)
    },
    run(args = [], env = {}) {
      return spawnSync('bash', [executable, ...args], {
        cwd: directory,
        env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, TMPDIR: temporary, HARNESS_LOG: log, ...env },
        encoding: 'utf8',
        timeout: 10_000,
      })
    },
  }
}

const record = `
const fs = require('node:fs');
const args = process.argv.slice(2);
fs.appendFileSync(process.env.HARNESS_LOG, JSON.stringify({ args, skip: process.env.CIPHERNODE_SKIP_PROOF_AGGREGATION }) + '\\n');
`

function integration(t) {
  const f = fixture(t, 'tests/integration/test.sh')
  for (const name of ['lib/prebuild', 'prebuild', 'persist', 'base', 'net']) {
    f.write(
      `tests/integration/${name}.sh`,
      `
const fs = require('node:fs');
fs.appendFileSync(process.env.HARNESS_LOG, JSON.stringify({ name: '${name}', skip: process.env.CIPHERNODE_SKIP_PROOF_AGGREGATION }) + '\\n');
process.exit(process.env.HARNESS_FAIL === '${name}' ? 17 : 0);
`,
    )
  }
  return f
}

test('the default integration command runs only existing scenarios after one prebuild', (t) => {
  const f = integration(t)
  const result = f.run()
  assert.equal(result.status, 0, result.stderr)
  assert.deepEqual(
    f.calls().map((c) => c.name),
    ['lib/prebuild', 'persist', 'base', 'net'],
  )
})

test('an individual integration scenario preserves the requested proof mode', (t) => {
  const f = integration(t)
  const result = f.run(['net', '--no-prebuild', '--skip-proof-aggregation', 'false'])
  assert.equal(result.status, 0, result.stderr)
  assert.deepEqual(f.calls(), [{ name: 'net', skip: 'false' }])
})

test('the CI prebuild entry point prepares fixtures exactly once', (t) => {
  const f = integration(t)
  const result = f.run(['prebuild'])
  assert.equal(result.status, 0, result.stderr)
  assert.deepEqual(
    f.calls().map((c) => c.name),
    ['lib/prebuild', 'prebuild'],
  )
})

test('an unknown integration scenario fails before prebuild', (t) => {
  const f = integration(t)
  assert.equal(f.run(['restart']).status, 1)
  assert.deepEqual(f.calls(), [])
})

for (const failed of ['lib/prebuild', 'persist', 'base', 'net']) {
  test(`integration propagates failure from ${failed}`, (t) => {
    const f = integration(t)
    const result = f.run([], { HARNESS_FAIL: failed })
    assert.equal(result.status, 17, result.stderr)
    assert.equal(f.calls().at(-1).name, failed)
  })
}

test('CRISP selects the named browser command result and propagates runner failure', (t) => {
  const f = fixture(t, 'examples/CRISP/scripts/test_e2e.sh')
  f.write('fake-bin/pnpm', `${record}\nprocess.exit(17);`)
  const result = f.run(['--ui'])
  assert.equal(result.status, 17, result.stderr)
  assert.equal(f.calls().length, 1)
  const { args } = f.calls()[0]
  assert.deepEqual(args.slice(0, 7), ['concurrently', '--kill-others', '--raw', '--names', 'dev,tests', '--success', 'command-tests'])
  assert.equal(args[7], './scripts/dev.sh')
  assert.match(args[8], /wait-on .* && pnpm synpress && pnpm playwright test$/)
})

function network(t) {
  const f = fixture(t, 'crates/net/tests/run.sh')
  f.write('fake-bin/git', `process.stdout.write('abcdef0\\n');`)
  f.write(
    'fake-bin/docker',
    `${record}
if (args[0] === 'build') process.exit(0);
if (args[0] === 'inspect') {
  const service = args.at(-1).replace('id-', '');
  if (process.env.INSPECT_FAIL === service) process.exit(1);
  const state = process.env.UNFINISHED === service ? 'running 0' : process.env.BAD_SERVICE === service ? 'exited 17' : 'exited 0';
  console.log(state);
  process.exit(0);
}
if (args[0] !== 'compose') process.exit(99);
const command = args[5];
if (command === 'up') process.exit(Number(process.env.UP_EXIT || 0));
if (command === 'ps') {
  const service = args.at(-1);
  if (process.env.MISSING_SERVICE !== service) console.log('id-' + service);
  process.exit(0);
}
if (command === 'logs') { console.log('preserved network log'); process.exit(0); }
if (command === 'down') process.exit(Number(process.env.DOWN_EXIT || 0));
process.exit(99);
`,
  )
  return f
}

const services = ['alice', 'bob', 'charlie', 'daniel', 'eve', 'fabian']

function checkNetworkCleanup(f) {
  const calls = f.calls().map((c) => c.args)
  const compose = calls.filter((args) => args[0] === 'compose')
  const project = compose[0][2]
  assert.match(project, /^interfold-net-/)
  assert.ok(compose.every((args) => args[1] === '--project-name' && args[2] === project))
  assert.deepEqual(compose.at(-1).slice(5), ['down', '--volumes', '--remove-orphans'])
  const logs = readdirSync(f.temporary)
  assert.equal(logs.length, 1)
  assert.equal(readFileSync(join(f.temporary, logs[0], 'compose.log'), 'utf8'), 'preserved network log\n')
}

test('network success requires all six completed containers and keeps logs', (t) => {
  const f = network(t)
  const result = f.run()
  assert.equal(result.status, 0, result.stderr)
  const calls = f.calls().map((c) => c.args)
  assert.deepEqual(
    calls.filter((args) => args[0] === 'inspect').map((args) => args.at(-1)),
    services.map((s) => `id-${s}`),
  )
  assert.deepEqual(calls.find((args) => args[0] === 'compose' && args[5] === 'up').slice(5), ['up', '--abort-on-container-failure'])
  checkNetworkCleanup(f)
})

for (const service of services) {
  test(`network propagates ${service}'s failure even when compose returns zero`, (t) => {
    const f = network(t)
    const result = f.run([], { BAD_SERVICE: service })
    assert.equal(result.status, 1, result.stderr)
    assert.match(result.stderr, new RegExp(`Network scenario ${service} failed`))
    checkNetworkCleanup(f)
  })
}

for (const env of [
  { MISSING_SERVICE: 'bob' },
  { UNFINISHED: 'charlie' },
  { INSPECT_FAIL: 'daniel' },
  { UP_EXIT: '17' },
  { DOWN_EXIT: '17' },
]) {
  test(`network fails closed for ${Object.keys(env)[0]}`, (t) => {
    const f = network(t)
    const result = f.run([], env)
    assert.equal(result.status, 1, result.stderr)
    checkNetworkCleanup(f)
  })
}

test('network runs use distinct Compose projects', (t) => {
  const f = network(t)
  assert.equal(f.run().status, 0)
  assert.equal(f.run().status, 0)
  const projects = f
    .calls()
    .filter((c) => c.args[0] === 'compose' && c.args[5] === 'up')
    .map((c) => c.args[2])
  assert.equal(new Set(projects).size, 2)
})
