// SPDX-License-Identifier: LGPL-3.0-only

import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

test('ZK sample support stays out of runtime dependencies, including aliases and target tables', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'interfold-sample-boundary-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  mkdirSync(join(dir, 'scripts'))
  mkdirSync(join(dir, 'crates/consumer'), { recursive: true })
  mkdirSync(join(dir, 'crates/zk/samples'), { recursive: true })
  copyFileSync(new URL('check-cargo-feature-containment.py', import.meta.url), join(dir, 'scripts/check.py'))
  writeFileSync(
    join(dir, 'Cargo.toml'),
    '[workspace]\nmembers = ["crates/consumer", "crates/zk/samples"]\n[workspace.dependencies]\nfixtures = { package = "e3-zk-samples", path = "crates/zk/samples" }\n',
  )
  const support = join(dir, 'crates/zk/samples/Cargo.toml')
  writeFileSync(support, '[package]\nname = "e3-zk-samples"\nversion = "0.1.0"\npublish = false\n')
  assert.equal(spawnSync('git', ['init', '--quiet'], { cwd: dir }).status, 0)
  const python = ['python3', 'python3.13', 'python3.12', 'python3.11', 'python3.10', 'python3.9'].find(
    (candidate) =>
      spawnSync(candidate, ['-c', 'import importlib.util as u, sys; sys.exit(0 if u.find_spec("tomllib") or u.find_spec("tomli") else 1)'])
        .status === 0,
  )
  assert.ok(python, 'install Python with tomllib or tomli')
  const check = (name, table, dependency = 'fixtures = { workspace = true }') => {
    writeFileSync(join(dir, 'crates/consumer/Cargo.toml'), `[package]\nname = "${name}"\nversion = "0.1.0"\n[${table}]\n${dependency}\n`)
    return spawnSync(python, ['scripts/check.py'], { cwd: dir, encoding: 'utf8' })
  }
  for (const table of ['dev-dependencies', "target.'cfg(unix)'.dev-dependencies"]) {
    const result = check('runtime', table)
    assert.equal(result.status, 0, result.stdout + result.stderr)
  }
  const tool = check('e3-zk-artifacts', 'dependencies')
  assert.equal(tool.status, 1, tool.stdout + tool.stderr)
  assert.match(tool.stdout, /e3-zk-samples is only allowed in dev-dependencies/)
  for (const table of ['dependencies', 'build-dependencies', "target.'cfg(unix)'.dependencies"]) {
    const result = check('runtime', table)
    assert.equal(result.status, 1, result.stdout + result.stderr)
    assert.match(result.stdout, /e3-zk-samples is only allowed in dev-dependencies/)
  }
  const renamed = check('runtime', 'dependencies', 'other = { package = "e3-zk-samples", path = "../zk/samples" }')
  assert.equal(renamed.status, 1, renamed.stdout + renamed.stderr)
  assert.match(renamed.stdout, /e3-zk-samples is only allowed in dev-dependencies/)
  writeFileSync(support, '[package]\nname = "e3-zk-samples"\nversion = "0.1.0"\n')
  const published = check('runtime', 'dev-dependencies')
  assert.equal(published.status, 1, published.stdout + published.stderr)
  assert.match(published.stdout, /must remain unpublished/)
})

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

// check:verifiers reads only the checked-out tree, so pre-push must stop the push of another branch that changes its inputs.
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
