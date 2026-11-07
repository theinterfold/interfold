// SPDX-License-Identifier: LGPL-3.0-only

import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { test } from 'node:test'

function repositoryFixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'interfold-repository-check-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  assert.equal(spawnSync('git', ['init', '--quiet'], { cwd: root }).status, 0)
  const write = (path, content) => {
    mkdirSync(dirname(join(root, path)), { recursive: true })
    writeFileSync(join(root, path), content)
  }
  mkdirSync(join(root, 'scripts/checks'), { recursive: true })
  for (const file of ['repository.sh', 'cargo-feature-containment.py', 'ciphernode-docker-members.py'])
    copyFileSync(new URL(file, import.meta.url), join(root, 'scripts/checks', file))
  // The boundary rules name real packages and have their own test; this stub checks the wiring.
  const boundaries = (status) =>
    write('scripts/checks/cargo-dependency-boundaries.py', `print("boundary stub")\nraise SystemExit(${status})\n`)
  boundaries(0)
  write('Cargo.toml', '[workspace]\nmembers = ["crates/core"]\n')
  write('crates/core/Cargo.toml', '[package]\nname = "core"\n')
  const startup =
    'fn validate_proof_aggregation_mode(skip: bool) {}\n' +
    'fn execute(config: Config) { validate_proof_aggregation_mode(config.skip_proof_aggregation()); }\n'
  write('crates/cli/src/start.rs', startup)
  write('crates/Dockerfile', 'COPY crates/core/Cargo.toml crates/core/Cargo.toml\n')
  const compose = (seconds) => `services:\n  node:\n    image: node\n    stop_grace_period: ${seconds}s\n`
  write('dappnode/docker-compose.yml', compose(61))
  write('deploy/docker-compose.yml', compose(120))
  const run = () => spawnSync('bash', [join(root, 'scripts/checks/repository.sh')], { cwd: root, encoding: 'utf8' })
  return { root, write, run, compose, startup, boundaries }
}

test('repository checks reject insufficient grace, missing Docker members, and production proof-skip features', (t) => {
  const { write, run, compose, boundaries } = repositoryFixture(t)
  const pass = run()
  assert.equal(pass.status, 0, pass.stdout + pass.stderr)
  boundaries(1)
  assert.equal(run().status, 1)
  assert.match(run().stdout, /boundary stub/)
  boundaries(0)
  write('deploy/docker-compose.yml', compose(60))
  assert.match(run().stdout, /must exceed 60 seconds/)
  assert.equal(run().status, 1)
  write('deploy/docker-compose.yml', 'services:\n  node:\n    image: node\n')
  assert.equal(run().status, 1)
  write(
    'deploy/docker-compose.yml',
    'services:\n  first:\n    stop_grace_period: 65s\n    stop_grace_period: 65s\n  second:\n    image: node\n',
  )
  assert.equal(run().status, 1)
  assert.match(run().stdout, /must declare exactly one/)
  for (const duration of ['"65s"', '1m', 'sixty-five', '0.065s']) {
    write('deploy/docker-compose.yml', `services:\n  node:\n    stop_grace_period: ${duration}\n`)
    assert.equal(run().status, 1, duration)
  }
  write('deploy/docker-compose.yml', compose(120))
  write('crates/Dockerfile', '')
  assert.equal(run().status, 1)
  assert.match(run().stdout, /omits workspace manifests/)
  write('crates/Dockerfile', 'COPY crates/core/Cargo.toml crates/core/Cargo.toml\n')
  write(
    'crates/core/Cargo.toml',
    '[package]\nname = "core"\n[features]\ndefault = ["indirect"]\nindirect = ["test-only-skip-proof-aggregation"]\n',
  )
  assert.equal(run().status, 1)
  assert.match(run().stdout, /Cargo development-only containment/)
})

test('repository checks reject a missing startup proof guard or its configuration call', (t) => {
  const { write, run, startup } = repositoryFixture(t)
  assert.equal(run().status, 0)
  for (const source of [
    startup.replace('fn validate_proof_aggregation_mode(skip: bool) {}\n', ''),
    startup.replace('validate_proof_aggregation_mode(config.skip_proof_aggregation());', ''),
  ]) {
    write('crates/cli/src/start.rs', source)
    const result = run()
    assert.equal(result.status, 1, result.stdout + result.stderr)
    assert.match(result.stdout, /validate_proof_aggregation_mode missing or no longer called/)
  }
})
