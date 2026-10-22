// SPDX-License-Identifier: LGPL-3.0-only

import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { test } from 'node:test'

// check:verifiers reads the checked-out tree, not an independently pushed branch.
test('the pre-push path helper stops a pushed branch that differs from HEAD in a filter path', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'interfold-pushed-paths-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const repo = join(dir, 'repo')
  const filter = join(dir, 'filter.yml')
  writeFileSync(filter, "circuits:\n  - 'circuits/**'\n")
  const env = {
    ...process.env,
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_AUTHOR_NAME: 'test',
    GIT_AUTHOR_EMAIL: 'test@example.com',
    GIT_COMMITTER_NAME: 'test',
    GIT_COMMITTER_EMAIL: 'test@example.com',
  }
  const git = (...args) => {
    const result = spawnSync('git', args, { cwd: repo, env, encoding: 'utf8' })
    assert.equal(result.status, 0, result.stderr)
    return result.stdout.trim()
  }
  const commit = (path, content) => {
    writeFileSync(join(repo, path), content)
    git('add', path)
    git('commit', '--quiet', '-m', path)
  }
  mkdirSync(join(repo, 'circuits'), { recursive: true })
  git('init', '--quiet', '-b', 'main')
  commit('circuits/x', 'a\n')
  commit('README', 'a\n')
  git('update-ref', 'refs/remotes/origin/main', 'HEAD')
  git('checkout', '--quiet', '-b', 'feature')
  commit('circuits/x', 'b\n')
  git('checkout', '--quiet', '-b', 'docs', 'main')
  commit('README', 'b\n')
  git('checkout', '--quiet', 'main')
  const push = (branch) =>
    spawnSync('bash', [new URL('pushed-paths-match.sh', import.meta.url).pathname, filter], {
      cwd: repo,
      env,
      input: `refs/heads/${branch} ${git('rev-parse', branch)} refs/heads/${branch} ${'0'.repeat(40)}\n`,
      encoding: 'utf8',
    })
  const stopped = push('feature')
  assert.equal(stopped.status, 2)
  assert.match(stopped.stderr, /Check out refs\/heads\/feature, then push again/)
  assert.equal(push('docs').status, 1)
  git('checkout', '--quiet', 'feature')
  assert.equal(push('feature').status, 0)
})

test('the production crypto filter covers owners, consumers, and tooling but excludes documentation', (t) => {
  const repo = mkdtempSync(join(tmpdir(), 'interfold-verifier-filter-'))
  t.after(() => rmSync(repo, { recursive: true, force: true }))
  const env = {
    ...process.env,
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_AUTHOR_NAME: 'test',
    GIT_AUTHOR_EMAIL: 'test@example.com',
    GIT_COMMITTER_NAME: 'test',
    GIT_COMMITTER_EMAIL: 'test@example.com',
  }
  const git = (...args) => {
    const result = spawnSync('git', args, { cwd: repo, env, encoding: 'utf8' })
    assert.equal(result.status, 0, result.stderr)
  }
  const cases = [
    ['scripts/circuits/artifacts.ts', 0],
    ['scripts/circuits/artifacts.test.ts', 0],
    ['scripts/circuits/README.md', 1],
    ['scripts/circuits/constants.ts', 0],
    ['scripts/circuits/build-pairs.json', 0],
    ['scripts/circuits/verifiers.ts', 0],
    ['scripts/circuits/verifiers.test.ts', 0],
    ['scripts/circuits/lint.sh', 0],
    ['scripts/circuits/test.sh', 0],
    ['crates/zk/build/src/identity.rs', 0],
    ['circuits/lib/src/core/circuit.nr', 0],
    ['crates/fhe-params/src/constants.rs', 0],
    ['crates/zk/config/src/constants.rs', 0],
    ['crates/committee/src/lib.rs', 0],
    ['packages/interfold-contracts/bfv.ts', 0],
    ['packages/interfold-contracts/crypto-config.json', 0],
    ['packages/interfold-sdk/src/utils.ts', 0],
    ['packages/interfold-dashboard/src/lib/adapt.ts', 0],
    ['templates/default/contracts/MyProgram.sol', 0],
    ['scripts/circuits/crypto-config.mjs', 0],
    ['.husky/pre-push', 0],
    ['Cargo.lock', 0],
  ]
  git('init', '--quiet', '-b', 'main')
  for (const [path] of cases) {
    mkdirSync(dirname(join(repo, path)), { recursive: true })
    writeFileSync(join(repo, path), 'before\n')
  }
  git('add', '.')
  git('commit', '--quiet', '-m', 'base')
  git('update-ref', 'refs/remotes/origin/main', 'HEAD')
  for (const [index, [path, expected]] of cases.entries()) {
    git('checkout', '--quiet', '-b', `case-${index}`, 'main')
    writeFileSync(join(repo, path), 'after\n')
    git('commit', '--quiet', '-am', 'change')
    const result = spawnSync(
      'bash',
      [new URL('pushed-paths-match.sh', import.meta.url).pathname, new URL('../../.github/filters/circuits.yml', import.meta.url).pathname],
      { cwd: repo, env, input: '', encoding: 'utf8' },
    )
    assert.equal(result.status, expected, `${path}: ${result.stdout}${result.stderr}`)
  }
})
