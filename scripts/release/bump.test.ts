// SPDX-License-Identifier: LGPL-3.0-only

import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { test } from 'node:test'

import { VersionBumper, main } from './bump'
import { CARGO_WORKSPACES, PACKAGE_FILES, releaseChannel, validateReleaseVersion } from './version.mjs'

const DAPPNODE_NETWORKS = ['mainnet', 'sepolia']

function fixture(t: { after: (fn: () => void) => void }) {
  const rootDir = mkdtempSync(join(tmpdir(), 'interfold-bump-'))
  t.after(() => rmSync(rootDir, { recursive: true, force: true }))
  const write = (path: string, content: string) => {
    mkdirSync(dirname(join(rootDir, path)), { recursive: true })
    writeFileSync(join(rootDir, path), content)
  }
  for (const path of PACKAGE_FILES) write(path, JSON.stringify({ name: path, version: '1.2.3' }) + '\n')
  write(
    'Cargo.toml',
    '[workspace.package]\nversion = "1.2.3"\n\n[workspace.dependencies]\na = { version = "1.2.3", path = "crates/a" }\nexternal = { version = "=7.8.9", features = ["x"] }\n\nb = { path = "crates/b", version = "1.2.3" }\n\n[other]\nversion = "do-not-change"\n',
  )
  write('crates/zk/prover/versions.json', '{"required_circuits_version":"1.2.3","bb":"keep"}\n')
  write('dappnode/dappnode_package.json', '{"version":"0.4.5","upstreamVersion":"1.2.3"}\n')
  write('dappnode/package.json', '{"version":"0.4.5"}\n')
  write('dappnode/package-lock.json', '{"version":"0.4.5","packages":{"":{"version":"0.4.5"}}}\n')
  write('dappnode/docker-compose.yml', 'UPSTREAM_VERSION: 1.2.3\n')
  write('dappnode/Dockerfile', 'ARG UPSTREAM_VERSION=1.2.3\n')
  for (const network of DAPPNODE_NETWORKS) {
    const name = `interfold-ciphernode-${network}.dnp.dappnode.eth`
    write(`dappnode/package_variants/${network}/dappnode_package.json`, JSON.stringify({ name }) + '\n')
    write(`dappnode/package_variants/${network}/docker-compose.yml`, `services:\n  ciphernode:\n    image: '${name}:0.4.5'\n`)
  }
  for (const workspace of CARGO_WORKSPACES) write(join(workspace, 'Cargo.lock'), 'old lock\n')
  write('pnpm-lock.yaml', 'old lock\n')
  write('CHANGELOG.md', 'old changelog\n')
  write('unrelated.txt', 'keep\n')
  const commands: { command: string; args: string[]; cwd: string }[] = []
  const state = { branch: 'release/1.3.0', status: '', fail: '' }
  const execute = (command: string, args: string[], cwd: string) => {
    commands.push({ command, args, cwd })
    if (`${command} ${args.join(' ')}`.includes(state.fail) && state.fail) throw new Error(`Failed ${state.fail}`)
    if (command === 'git' && args[0] === 'symbolic-ref') return state.branch
    if (command === 'git' && args[0] === 'status') return state.status
    if (command === 'cargo') writeFileSync(join(cwd, 'Cargo.lock'), 'updated lock\n')
    if (command === 'pnpm' && args[0] === 'install') write('pnpm-lock.yaml', 'updated lock\n')
    if (command === 'pnpm' && args[0] === 'auto-changelog') write('CHANGELOG.md', 'updated changelog\n')
    return ''
  }
  const read = (path: string) => readFileSync(join(rootDir, path), 'utf8')
  return { rootDir, execute, commands, read, state }
}

test('default preparation updates all manifests, local Cargo pins and required locks without git/publication', (t) => {
  const f = fixture(t)
  new VersionBumper('v1.3.0', {}, f).bumpAll()
  assert.equal(validateReleaseVersion('1.3.0', f.rootDir), '1.3.0')
  assert.equal(JSON.parse(f.read('dappnode/dappnode_package.json')).version, '0.5.0')
  for (const network of DAPPNODE_NETWORKS) {
    assert.ok(f.read(`dappnode/package_variants/${network}/docker-compose.yml`).includes(`${network}.dnp.dappnode.eth:0.5.0'`))
  }
  assert.match(f.read('Cargo.toml'), /a = \{ version = "1.3.0", path/)
  assert.match(f.read('Cargo.toml'), /b = \{ path = "crates\/b", version = "1.3.0"/)
  assert.match(f.read('Cargo.toml'), /external = \{ version = "=7.8.9"/)
  assert.match(f.read('Cargo.toml'), /version = "do-not-change"/)
  assert.equal(f.read('unrelated.txt'), 'keep\n')
  assert.equal(
    f.commands.some(({ command }) => command === 'git' || command === 'npm'),
    false,
  )
  for (const workspace of CARGO_WORKSPACES) assert.equal(f.read(join(workspace, 'Cargo.lock')), 'updated lock\n')
  const format = f.commands.find(({ args }) => args.includes('prettier'))!
  assert.equal(format.args.includes('unrelated.txt'), false)
  assert.equal(format.args.includes('.'), false)
  assert.equal(f.read('CHANGELOG.md'), 'updated changelog\n')
})

test('prerelease uses the release channel owner and leaves the entire DAppNode wrapper unchanged', (t) => {
  const f = fixture(t)
  const before = f.read('dappnode/dappnode_package.json')
  new VersionBumper('1.3.0-dev.1', {}, f).bumpAll()
  assert.equal(releaseChannel('1.3.0-dev.1'), 'dev')
  assert.equal(validateReleaseVersion('1.3.0-dev.1', f.rootDir), '1.3.0-dev.1')
  assert.equal(f.read('dappnode/dappnode_package.json'), before)
  assert.equal(
    f.commands.some(({ args }) => args.some((arg) => arg.startsWith('dappnode/'))),
    false,
  )
})

test('dry run invokes no commands and does not write release files, even with commit/push requested', (t) => {
  const f = fixture(t)
  const files = [
    'Cargo.toml',
    ...PACKAGE_FILES,
    'pnpm-lock.yaml',
    'Cargo.lock',
    'CHANGELOG.md',
    'crates/zk/prover/versions.json',
    'dappnode/dappnode_package.json',
  ]
  const before = files.map(f.read)
  new VersionBumper('1.3.0', { dryRun: true, commit: true, push: true }, f).bumpAll()
  assert.deepEqual(files.map(f.read), before)
  assert.deepEqual(f.commands, [])
})

for (const failure of ['pnpm install', 'cargo update', 'pnpm auto-changelog', 'pnpm exec prettier']) {
  test(`${failure} failure stops before staging, committing or pushing`, (t) => {
    const f = fixture(t)
    f.state.fail = failure
    assert.throws(() => new VersionBumper('1.3.0', { commit: true, push: true }, f).bumpAll(), /Failed/)
    assert.equal(
      f.commands.some(({ command, args }) => command === 'git' && ['add', 'commit', 'push'].includes(args[0])),
      false,
    )
  })
}

test('explicit commit stages only release outputs and pushes only with the additional flag', (t) => {
  const f = fixture(t)
  new VersionBumper('1.3.0', { commit: true, push: true }, f).bumpAll()
  const git = f.commands.filter(({ command }) => command === 'git').map(({ args }) => args)
  const staged = git.find((args) => args[0] === 'add')!
  assert.equal(staged[1], '--')
  assert.ok(staged.includes('Cargo.toml'))
  assert.ok(staged.includes('pnpm-lock.yaml'))
  for (const network of DAPPNODE_NETWORKS) assert.ok(staged.includes(`dappnode/package_variants/${network}/docker-compose.yml`))
  assert.equal(staged.includes('.'), false)
  assert.equal(staged.includes('unrelated.txt'), false)
  assert.deepEqual(git.at(-1), ['push', 'origin', 'release/1.3.0'])
  assert.equal(
    git.some((args) => args[0] === 'tag'),
    false,
  )
  const local = fixture(t)
  new VersionBumper('1.3.0', { commit: true }, local).bumpAll()
  assert.equal(
    local.commands.some(({ args }) => args[0] === 'push'),
    false,
  )
})

test('commit safeguards reject protected branches, dirty trees and implicit push before writing', (t) => {
  for (const branch of ['main', 'dev', '']) {
    const f = fixture(t)
    f.state.branch = branch
    const before = f.read('Cargo.toml')
    assert.throws(() => new VersionBumper('1.3.0', { commit: true }, f).bumpAll(), /release branch/)
    assert.equal(f.read('Cargo.toml'), before)
  }
  const f = fixture(t)
  f.state.status = ' M unrelated.txt'
  assert.throws(() => new VersionBumper('1.3.0', { commit: true }, f).bumpAll(), /clean index/)
  assert.throws(() => new VersionBumper('1.3.0', { push: true }, f).bumpAll(), /requires --commit/)
  assert.throws(() => main(['1.3.0', '--no-push']), /Unknown option/)
})

test('stable wrapper progression follows upstream major, patch and rejects decreases', (t) => {
  for (const [next, expected] of [
    ['2.0.0', '1.0.0'],
    ['1.2.4', '0.4.6'],
    ['1.2.3', '0.4.6'],
  ]) {
    const f = fixture(t)
    new VersionBumper(next, {}, f).bumpAll()
    assert.equal(JSON.parse(f.read('dappnode/dappnode_package.json')).version, expected)
  }
  const f = fixture(t)
  assert.throws(() => new VersionBumper('1.1.0', {}, f).bumpAll(), /cannot decrease/)
  assert.deepEqual(f.commands, [])
})
