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
  for (const path of ['scripts/checks', 'crates/consumer', 'crates/zk/samples']) mkdirSync(join(dir, path), { recursive: true })
  copyFileSync(new URL('cargo-feature-containment.py', import.meta.url), join(dir, 'scripts/checks/check.py'))
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
    return spawnSync(python, ['scripts/checks/check.py'], { cwd: dir, encoding: 'utf8' })
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

test('shared fixture support stays dev-only, unpublished and independent of internal crates', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'interfold-fixture-boundary-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  for (const path of ['scripts/checks', 'crates/consumer', 'crates/support']) mkdirSync(join(dir, path), { recursive: true })
  copyFileSync(new URL('cargo-feature-containment.py', import.meta.url), join(dir, 'scripts/checks/check.py'))
  assert.equal(spawnSync('git', ['init', '--quiet'], { cwd: dir }).status, 0)
  const python = ['python3', 'python3.13', 'python3.12', 'python3.11', 'python3.10', 'python3.9'].find(
    (candidate) =>
      spawnSync(candidate, ['-c', 'import importlib.util as u, sys; sys.exit(0 if u.find_spec("tomllib") or u.find_spec("tomli") else 1)'])
        .status === 0,
  )
  assert.ok(python, 'install Python with tomllib or tomli')
  const check = () => spawnSync(python, ['scripts/checks/check.py'], { cwd: dir, encoding: 'utf8' })
  const support = join(dir, 'crates/support/Cargo.toml')
  const consumer = join(dir, 'crates/consumer/Cargo.toml')
  for (const name of ['e3-test-support', 'e3-bfv-test-support']) {
    writeFileSync(
      join(dir, 'Cargo.toml'),
      `[workspace]\n[workspace.dependencies]\nfixtures = { package = "${name}", path = "crates/support" }\n`,
    )
    writeFileSync(support, `[package]\nname = "${name}"\nversion = "0.1.0"\npublish = false\n`)
    for (const table of ['dev-dependencies', "target.'cfg(unix)'.dev-dependencies"]) {
      writeFileSync(consumer, `[package]\nname = "consumer"\nversion = "0.1.0"\n[${table}]\nfixtures = { workspace = true }\n`)
      const result = check()
      assert.equal(result.status, 0, result.stdout + result.stderr)
    }
    for (const table of ['dependencies', 'build-dependencies', "target.'cfg(unix)'.dependencies"]) {
      writeFileSync(consumer, `[package]\nname = "consumer"\nversion = "0.1.0"\n[${table}]\nfixtures = { workspace = true }\n`)
      const result = check()
      assert.equal(result.status, 1, result.stdout + result.stderr)
      assert.match(result.stdout, /only allowed in dev-dependencies/)
    }
    writeFileSync(consumer, '[package]\nname = "consumer"\nversion = "0.1.0"\n')
    writeFileSync(support, `[package]\nname = "${name}"\nversion = "0.1.0"\n`)
    assert.match(check().stdout, /must remain unpublished/)
    writeFileSync(
      support,
      `[package]\nname = "${name}"\nversion = "0.1.0"\npublish = false\n[target.'cfg(unix)'.dependencies]\nnode = { package = "e3-ciphernode-builder", path = "../builder" }\n`,
    )
    assert.match(check().stdout, /cannot depend on internal crate e3-ciphernode-builder/)
  }
  writeFileSync(support, '[package]\nname = "e3-test-support"\nversion = "0.1.0"\npublish = false\n')
  writeFileSync(
    consumer,
    '[package]\nname = "consumer"\nversion = "0.1.0"\n[dependencies]\nsystem = { package = "e3-tests", path = "../tests" }\n',
  )
  const system = check()
  assert.equal(system.status, 1, system.stdout + system.stderr)
  assert.match(system.stdout, /system-test composition cannot be a production dependency/)
})
