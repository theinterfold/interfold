// SPDX-License-Identifier: LGPL-3.0-only

import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..')

function fixture(t, script) {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'interfold-harness-test-')))
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

function timing(t, script, env = {}) {
  const f = fixture(t, 'tests/integration/lib/utils.sh')
  f.write(
    'fake-bin/curl',
    `${record}
if (process.env.RPC_TRANSPORT_FAIL) process.exit(17);
const request = JSON.parse(args.at(-1));
console.log(JSON.stringify((process.env.RPC_ERROR || (process.env.RPC_MINE_ERROR && request.method === 'evm_mine')) ? { error: { message: 'rejected' } } :
  { result: request.method === 'eth_getBlockByNumber' ? { timestamp: '0x3e8' } : '0x0' }));`,
  )
  const result = spawnSync(
    'bash',
    ['-euo', 'pipefail', '-c', `source "$1"; ${script}`, '--', join(f.directory, 'tests/integration/lib/utils.sh')],
    {
      env: {
        ...process.env,
        PATH: `${f.directory}/fake-bin:${process.env.PATH}`,
        HARNESS_LOG: join(f.directory, 'commands.jsonl'),
        ...env,
      },
      encoding: 'utf8',
      timeout: 10_000,
    },
  )
  return { ...f, result }
}

for (const timeout of [1300, 3600]) {
  test(`integration input window covers the ${timeout}s DKG budget and advances without sleeping`, (t) => {
    const f = timing(
      t,
      'set_integration_input_window; echo "$INPUT_WINDOW_START $INPUT_WINDOW_END"; advance_evm_timestamp "$INPUT_WINDOW_END"',
      { INTEGRATION_DKG_TIMEOUT: String(timeout) },
    )
    assert.equal(f.result.status, 0, f.result.stderr)
    assert.equal(f.result.stdout.trim(), `1060 ${1060 + timeout + 300}`)
    const requests = f.calls().map((c) => JSON.parse(c.args.at(-1)))
    const mine = requests.filter((c) => c.method === 'evm_mine')
    assert.equal(mine.length, 1)
    assert.deepEqual(mine[0].params, [1060 + timeout + 300])
  })
}

test('chain time does not move backward or mine again at the same timestamp', (t) => {
  const f = timing(t, 'advance_evm_timestamp 999; advance_evm_timestamp 1000')
  assert.equal(f.result.status, 0, f.result.stderr)
  assert.ok(f.calls().every((c) => JSON.parse(c.args.at(-1)).method === 'eth_getBlockByNumber'))
})

for (const env of [{ RPC_ERROR: '1' }, { RPC_MINE_ERROR: '1' }, { RPC_TRANSPORT_FAIL: '1' }, { INTEGRATION_DKG_TIMEOUT: 'invalid' }]) {
  test(`integration timing fails closed for ${Object.keys(env)[0]}`, (t) => {
    const f = timing(t, 'set_integration_input_window; advance_evm_timestamp "$INPUT_WINDOW_END"', env)
    assert.notEqual(f.result.status, 0, f.result.stderr)
    if (!env.RPC_MINE_ERROR) assert.ok(f.calls().every((c) => JSON.parse(c.args.at(-1)).method === 'eth_getBlockByNumber'))
  })
}

function isolatedCrisp(t) {
  const f = fixture(t, 'scripts/run-crisp-test.sh')
  f.write('fake-bin/bb', 'process.exit(0);')
  f.write('existing-bin/interfold', 'original installed binary')
  writeFileSync(join(f.directory, 'notes.txt'), 'unrelated caller data')
  f.write(
    'fake-bin/git',
    `${record}
if (args[2] === 'status') { if (process.env.WORKTREE_DIRTY) console.log(' M changed.rs'); process.exit(process.env.WORKTREE_STATUS_FAIL ? 17 : 0); }
if (args[3] === 'remove' && process.env.WORKTREE_REMOVE_FAIL) process.exit(17);
if (args[2] === 'worktree' && args[3] === 'add') {
  if (process.env.WORKTREE_ADD_FAIL) process.exit(17);
  fs.mkdirSync(require('node:path').join(args[5], 'examples/CRISP'), { recursive: true });
} else if (args[2] !== 'submodule' && !(args[2] === 'worktree' && args[3] === 'remove')) process.exit(99);`,
  )
  f.write(
    'fake-bin/rm',
    `${record}
if (args.length !== 2 || args[0] !== '-rf' || !args[1].startsWith(process.env.TMPDIR + '/interfold-crisp-e2e.')) process.exit(99);
fs.rmSync(args[1], { recursive: true });`,
  )
  f.write(
    'fake-bin/pnpm',
    `const fs = require('node:fs');
const args = process.argv.slice(2);
fs.appendFileSync(process.env.HARNESS_LOG, JSON.stringify({ args, cwd: process.cwd(), installRoot: process.env.CARGO_INSTALL_ROOT }) + '\\n');
fs.mkdirSync(process.env.CARGO_INSTALL_ROOT + '/bin', { recursive: true });
fs.writeFileSync(process.env.CARGO_INSTALL_ROOT + '/bin/interfold', 'isolated binary');
process.exit(process.env.HARNESS_FAIL === args[0] ? 17 : 0);`,
  )
  return f
}

test('isolated CRISP preserves caller files, installs locally, and forwards test arguments', (t) => {
  const f = isolatedCrisp(t)
  const installed = readFileSync(join(f.directory, 'existing-bin/interfold'), 'utf8')
  const result = f.run(['--ui'])
  assert.equal(result.status, 0, result.stderr)
  const commands = f.calls().filter((c) => c.installRoot)
  assert.deepEqual(
    commands.map((c) => c.args),
    [['dev:setup'], ['test:e2e', '--ui']],
  )
  assert.ok(commands.every((c) => c.cwd.startsWith(f.temporary + '/') && c.cwd.endsWith('/source/examples/CRISP')))
  assert.ok(commands.every((c) => c.installRoot === resolve(c.cwd, '../../../cli')))
  assert.equal(readFileSync(join(f.directory, 'notes.txt'), 'utf8'), 'unrelated caller data')
  assert.equal(readFileSync(join(f.directory, 'existing-bin/interfold'), 'utf8'), installed)
  assert.deepEqual(readdirSync(f.temporary), [])
})

for (const failed of ['dev:setup', 'test:e2e']) {
  test(`isolated CRISP propagates ${failed} failure and retains its checkout`, (t) => {
    const f = isolatedCrisp(t)
    const result = f.run([], { HARNESS_FAIL: failed })
    assert.equal(result.status, 17, result.stderr)
    assert.equal(f.calls().at(-1).args[0], failed)
    assert.match(result.stderr, /Retained checkout and build files/)
    assert.equal(readdirSync(f.temporary).length, 1)
  })
}

test('isolated CRISP rejects pending source changes before creating a worktree', (t) => {
  const f = isolatedCrisp(t)
  const result = f.run([], { WORKTREE_DIRTY: '1' })
  assert.equal(result.status, 1, result.stderr)
  assert.equal(f.calls().length, 1)
  assert.deepEqual(readdirSync(f.temporary), [])
})

test('isolated CRISP stops if its checkout cannot be created', (t) => {
  const f = isolatedCrisp(t)
  assert.equal(f.run([], { WORKTREE_ADD_FAIL: '1' }).status, 17)
  assert.ok(f.calls().every((c) => !c.installRoot))
})

test('isolated CRISP stops if source status cannot be read', (t) => {
  const f = isolatedCrisp(t)
  assert.equal(f.run([], { WORKTREE_STATUS_FAIL: '1' }).status, 17)
  assert.equal(f.calls().length, 1)
  assert.deepEqual(readdirSync(f.temporary), [])
})

test('isolated CRISP reports cleanup failure and retains its test files', (t) => {
  const f = isolatedCrisp(t)
  assert.equal(f.run([], { WORKTREE_REMOVE_FAIL: '1' }).status, 17)
  assert.equal(readdirSync(f.temporary).length, 1)
  assert.equal(f.calls().at(-1).args[3], 'remove')
})

test('isolated CRISP preserves a real Git checkout and its submodule', (t) => {
  const f = isolatedCrisp(t)
  rmSync(join(f.directory, 'fake-bin/git'))
  mkdirSync(join(f.directory, 'examples/CRISP'), { recursive: true })
  writeFileSync(join(f.directory, 'examples/CRISP/.keep'), '')
  writeFileSync(join(f.directory, '.gitignore'), '/fake-bin/\n/existing-bin/\n/fixture-dependency/\n/notes.txt\n/commands.jsonl\n/tmp/\n')
  const git = (...args) => {
    const result = spawnSync('git', ['-C', f.directory, '-c', 'core.hooksPath=/dev/null', ...args], { encoding: 'utf8', timeout: 10_000 })
    assert.equal(result.status, 0, result.stderr)
    return result.stdout.trim()
  }
  git('init', '-q')
  git('config', 'core.hooksPath', '/dev/null')
  const commit = (...args) =>
    git(
      ...args,
      '-c',
      'user.name=Harness Test',
      '-c',
      'user.email=harness@example.invalid',
      '-c',
      'commit.gpgsign=false',
      'commit',
      '-qm',
      'fix: add isolated fixture',
    )
  const dependency = join(f.directory, 'fixture-dependency')
  git('init', '-q', dependency)
  writeFileSync(join(dependency, 'README'), 'local dependency')
  git('-C', dependency, 'add', 'README')
  commit('-C', dependency)
  git('-c', 'protocol.file.allow=always', 'submodule', 'add', dependency, 'examples/CRISP/dependency')
  git('add', 'scripts/run-crisp-test.sh', 'examples/CRISP/.keep', '.gitignore', '.gitmodules', 'examples/CRISP/dependency')
  commit()
  const head = git('rev-parse', 'HEAD')
  const result = f.run([], { GIT_ALLOW_PROTOCOL: 'file' })
  assert.equal(result.status, 0, result.stderr)
  assert.equal(git('rev-parse', 'HEAD'), head)
  assert.equal(git('status', '--porcelain'), '')
  assert.equal(
    git('worktree', 'list', '--porcelain')
      .split('\n')
      .filter((line) => line.startsWith('worktree ')).length,
    1,
  )
  assert.equal(f.calls().filter((c) => c.installRoot).length, 2)
  assert.equal(readFileSync(join(f.directory, 'notes.txt'), 'utf8'), 'unrelated caller data')
  assert.equal(readFileSync(join(f.directory, 'examples/CRISP/dependency/README'), 'utf8'), 'local dependency')
  assert.deepEqual(readdirSync(f.temporary), [])
})

for (const hasEnv of [false, true]) {
  test(`sale rehearsal reports missing ${hasEnv ? 'credentials' : 'env file'} before any command`, (t) => {
    const f = fixture(t, 'scripts/cca-demo.sh')
    if (hasEnv) {
      mkdirSync(join(f.directory, 'packages/interfold-contracts'), { recursive: true })
      writeFileSync(join(f.directory, 'packages/interfold-contracts/.env'), 'PRIVATE_KEY=\nSAFE_API_KEY=\n')
    }
    f.write('fake-bin/pnpm', `${record}\nprocess.exit(99);`)
    const result = f.run([], { PRIVATE_KEY: '', SAFE_API_KEY: '' })
    assert.equal(result.status, 1, result.stderr)
    assert.doesNotMatch(result.stderr, /command not found/)
    assert.match(result.stdout, hasEnv ? /PRIVATE_KEY not found/ : /\.env not found/)
    assert.deepEqual(f.calls(), [])
  })
}

test('sale rehearsal loads configuration and propagates compile failure without deploying', (t) => {
  const f = fixture(t, 'scripts/cca-demo.sh')
  mkdirSync(join(f.directory, 'packages/interfold-contracts'), { recursive: true })
  writeFileSync(join(f.directory, 'packages/interfold-contracts/.env'), 'PRIVATE_KEY=fixture-only\nSAFE_API_KEY=fixture-only\n')
  f.write('fake-bin/pnpm', `${record}\nprocess.exit(17);`)
  const result = f.run()
  assert.equal(result.status, 17, result.stderr)
  assert.deepEqual(
    f.calls().map((c) => c.args),
    [['compile']],
  )
})

for (const tool of ['node', 'jq', 'envsubst']) {
  test(`DAppNode tests fail before setup when ${tool} is unavailable`, () => {
    const result = spawnSync(
      'bash',
      ['-c', 'command() { [[ "$2" != "$MISSING_TOOL" ]]; }; source "$1"', '--', join(repo, 'dappnode/tests/test-hardening.sh')],
      {
        env: { ...process.env, MISSING_TOOL: tool },
        encoding: 'utf8',
        timeout: 10_000,
      },
    )
    assert.equal(result.status, 1, result.stderr)
    assert.match(result.stderr, new RegExp(`Required test tool is missing: ${tool}`))
    assert.doesNotMatch(result.stdout, /PASS/)
  })
}
