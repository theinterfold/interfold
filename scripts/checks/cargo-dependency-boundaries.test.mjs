// SPDX-License-Identifier: LGPL-3.0-only

import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

const SHARED = [
  'e3-bfv-client',
  'e3-fhe-params',
  'e3-zk-config',
  'e3-zk-witness',
  'e3-polynomial',
  'e3-polynomial-fhe',
  'e3-committee',
  'e3-parity-matrix',
  'e3-safe',
]
// The permitted graph in miniature: application and node share libraries, tests may cross, and
// packages outside both roles (the SDK here) are not constrained.
const PERMITTED = {
  'e3-compute-provider':
    '[dependencies]\ne3-bfv-client = { path = "../e3-bfv-client" }\n[dev-dependencies]\ne3-events = { path = "../e3-events" }',
  'e3-openvm-types': '[dependencies]\ne3-compute-provider = { workspace = true }',
  'e3-openvm-host': '[dependencies]\ne3-openvm-types = { path = "../e3-openvm-types" }',
  'e3-program-server': '[dependencies]\ne3-compute-provider = { path = "../e3-compute-provider" }',
  'e3-program-runner':
    '[dependencies]\ne3-openvm-host = { path = "../e3-openvm-host" }\ne3-program-server = { path = "../e3-program-server" }',
  'interfold-openvm-prover': '',
  'e3-user-program-runner': '[dependencies]\ne3-program-runner = { path = "../e3-program-runner" }',
  'e3-openvm-guest': '[dependencies]\ne3-safe = { path = "../e3-safe" }',
  'e3-bfv-client': '[dependencies]\ne3-fhe-params = { path = "../e3-fhe-params" }',
  'e3-cli':
    '[dependencies]\ne3-entrypoint = { path = "../e3-entrypoint" }\n[dev-dependencies]\ne3-program-runner = { path = "../e3-program-runner" }',
  'e3-entrypoint': '[dependencies]\ne3-events = { path = "../e3-events" }\ne3-bfv-client = { path = "../e3-bfv-client" }',
  'e3-events': '[dependencies]\ne3-utils = { path = "../e3-utils" }',
  'e3-utils': '',
  'e3-sdk': '[dependencies]\ne3-openvm-types = { path = "../e3-openvm-types", optional = true }',
  ...Object.fromEntries(SHARED.slice(1).map((name) => [name, ''])),
}
// A separate workspace, like the template's, resolves inherited dependencies from its own root,
// where `runtime` names a permitted package rather than the root workspace's `e3-events`.
const TEMPLATE = 'templates/default'
const TEMPLATE_WORKSPACE = (runtime = 'e3-compute-provider') =>
  `[workspace]\nmembers = ["program"]\n[workspace.dependencies]\nruntime = { package = "${runtime}", path = "../../crates/${runtime}" }\n`

test('application execution and the node binary link only what the boundary permits', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'interfold-dependency-boundary-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  mkdirSync(join(dir, 'scripts/checks'), { recursive: true })
  copyFileSync(new URL('cargo-dependency-boundaries.py', import.meta.url), join(dir, 'scripts/checks/check.py'))
  assert.equal(spawnSync('git', ['init', '--quiet'], { cwd: dir }).status, 0)
  const python = ['python3', 'python3.13', 'python3.12', 'python3.11', 'python3.10', 'python3.9'].find(
    (candidate) =>
      spawnSync(candidate, ['-c', 'import importlib.util as u, sys; sys.exit(0 if u.find_spec("tomllib") or u.find_spec("tomli") else 1)'])
        .status === 0,
  )
  assert.ok(python, 'install Python with tomllib or tomli')

  const manifest = (name, body) => `[package]\nname = "${name}"\nversion = "0.1.0"\n${body}\n`
  const check = (changes = {}, { template = TEMPLATE_WORKSPACE(), omit } = {}) => {
    rmSync(join(dir, 'crates'), { recursive: true, force: true })
    const packages = { ...PERMITTED, ...changes }
    for (const [name, body] of Object.entries(packages)) {
      if (name === omit) continue
      mkdirSync(join(dir, 'crates', name), { recursive: true })
      writeFileSync(join(dir, 'crates', name, 'Cargo.toml'), manifest(name, body))
    }
    const members = Object.keys(packages).map((name) => `"crates/${name}"`)
    writeFileSync(
      join(dir, 'Cargo.toml'),
      `[workspace]\nmembers = [${members}]\n[workspace.dependencies]\ne3-compute-provider = { path = "crates/e3-compute-provider" }\nruntime = { package = "e3-events", path = "crates/e3-events" }\n`,
    )
    mkdirSync(join(dir, TEMPLATE, 'program'), { recursive: true })
    writeFileSync(join(dir, TEMPLATE, 'Cargo.toml'), template)
    writeFileSync(join(dir, TEMPLATE, 'program/Cargo.toml'), manifest('e3-user-program', '[dependencies]\nruntime = { workspace = true }'))
    return spawnSync(python, ['scripts/checks/check.py'], { cwd: dir, encoding: 'utf8' })
  }
  const rejects = (result, pattern) => {
    assert.equal(result.status, 1, result.stdout + result.stderr)
    assert.match(result.stdout, pattern)
  }

  const permitted = check()
  assert.equal(permitted.status, 0, permitted.stdout + permitted.stderr)

  const events = /application execution links e3-events: e3-program-server -> e3-events\n/
  for (const table of ['dependencies', 'build-dependencies', "target.'cfg(unix)'.dependencies"]) {
    rejects(check({ 'e3-program-server': `[${table}]\ne3-events = { path = "../e3-events" }` }), events)
  }
  rejects(check({ 'e3-program-server': '[dependencies]\ne3-events = { path = "../e3-events", optional = true }' }), events)
  rejects(check({ 'e3-program-server': '[dependencies]\nrenamed = { package = "e3-events", path = "../e3-events" }' }), events)
  rejects(check({ 'e3-program-server': '[dependencies]\nruntime = { workspace = true }' }), events)

  // Only the first crossing is reported, not what the forbidden package links in turn.
  const shared = check({ 'e3-fhe-params': '[dependencies]\ne3-events = { path = "../e3-events" }' })
  rejects(shared, /application execution links e3-events: e3-compute-provider -> e3-bfv-client -> e3-fhe-params -> e3-events\n/)
  assert.doesNotMatch(shared.stdout, /e3-utils/)
  // A general utility is not a reviewed shared library.
  rejects(
    check({ 'e3-openvm-host': '[dependencies]\ne3-utils = { path = "../e3-utils" }' }),
    /application execution links e3-utils: e3-openvm-host -> e3-utils/,
  )
  rejects(check({}, { template: TEMPLATE_WORKSPACE('e3-events') }), /application execution links e3-events: e3-user-program -> e3-events/)

  rejects(
    check({
      'e3-entrypoint':
        '[dependencies]\ne3-events = { path = "../e3-events" }\nhost = { package = "e3-openvm-host", path = "../e3-openvm-host" }',
    }),
    /the node binary links application execution: e3-cli -> e3-entrypoint -> e3-openvm-host\n/,
  )
  rejects(check({}, { omit: 'e3-openvm-host' }), /e3-openvm-host is no longer a package here/)
})
