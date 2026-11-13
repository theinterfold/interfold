// SPDX-License-Identifier: LGPL-3.0-only

import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test, type TestContext } from 'node:test'

function fixture(t: TestContext) {
  const root = mkdtempSync(join(tmpdir(), 'interfold-prebuild-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const lib = join(root, 'tests/integration/lib')
  mkdirSync(lib, { recursive: true })
  for (const file of ['prebuild.sh', 'utils.sh']) {
    copyFileSync(join(__dirname, '../../tests/integration/lib', file), join(lib, file))
  }
  mkdirSync(join(root, 'crates/zk/prover'), { recursive: true })
  copyFileSync(join(__dirname, '../../crates/zk/prover/versions.json'), join(root, 'crates/zk/prover/versions.json'))
  const bin = join(root, 'bin')
  mkdirSync(bin)
  writeFileSync(join(bin, 'cargo'), '#!/bin/sh\nexit 0\n', { mode: 0o755 })
  writeFileSync(join(bin, 'bb'), '#!/bin/sh\nprintf "6.0.0\\n"\n', { mode: 0o755 })
  writeFileSync(
    join(bin, 'pnpm'),
    `#!/bin/bash
set -eu
printf '%s\\n' "$*" >> "$CALLS"
seed() {
  for preset in insecure-64 secure-8192; do
    mkdir -p "dist/circuits/$preset/minimum"
    printf '{"source":"%s"}\\n' "$1" > "dist/circuits/$preset/minimum/artifact.json"
  done
}
case "$*" in
  'store:circuits pull')
    if [[ "\${PULL_STATUS:-0}" != 0 ]]; then exit "$PULL_STATUS"; fi
    seed matching ;;
  'store:circuits pull --latest') seed unrelated ;;
  'build:circuits --preset all --committee all'*)
    if [[ "\${BUILD_STATUS:-0}" != 0 ]]; then exit "$BUILD_STATUS"; fi
    seed matching ;;
  'build:circuits prepare-vk-commitments')
    if grep -q unrelated dist/circuits/insecure-64/minimum/artifact.json; then exit 42; fi
    exit "\${CATALOGUE_STATUS:-0}" ;;
  'check:crypto-config --full') exit "\${VALIDATION_STATUS:-0}" ;;
  'generate:verifiers --check'*) exit "\${VERIFIER_STATUS:-0}" ;;
  'store:circuits checksums --dir '*)
    node - "$4" <<'JS'
const { createHash } = require('node:crypto')
const { readdirSync, readFileSync, writeFileSync } = require('node:fs')
const { join } = require('node:path')
const dir = process.argv[2]
const files = Object.fromEntries(readdirSync(dir, { recursive: true, withFileTypes: true })
  .filter(entry => entry.isFile())
  .map(entry => {
    const path = join(entry.parentPath, entry.name).slice(dir.length + 1)
    return [path, createHash('sha256').update(readFileSync(join(dir, path))).digest('hex')]
  }))
writeFileSync(join(dir, 'checksums.json'), JSON.stringify({ algorithm: 'sha256', files }))
JS
    ;;
esac
`,
    { mode: 0o755 },
  )
  return {
    root,
    calls: () => readFileSync(join(root, 'calls'), 'utf8').trim().split('\n'),
    run: (env: Record<string, string> = {}) =>
      spawnSync('bash', [join(lib, 'prebuild.sh')], {
        cwd: root,
        encoding: 'utf8',
        env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, CALLS: join(root, 'calls'), FULL_PROOF_AGGREGATION: 'true', ...env },
      }),
  }
}

test('full-proof prebuild reuses matching artifacts without taking the published branch tip', (t) => {
  const f = fixture(t)
  const result = f.run()
  assert.equal(result.status, 0, result.stderr + result.stdout)
  assert.ok(f.calls().includes('store:circuits pull'))
  assert.ok(!f.calls().some((call) => call.includes('--latest') || call.startsWith('build:circuits --preset all')))
  assert.ok(f.calls().includes('check:crypto-config --full'))
  for (const preset of ['insecure-64', 'secure-8192']) {
    const staged = join(f.root, 'tests/integration/.interfold/noir/circuits', preset, 'minimum/artifact.json')
    assert.equal(JSON.parse(readFileSync(staged, 'utf8')).source, 'matching')
  }
})

test('full-proof prebuild builds the complete matrix when matching artifacts are unpublished', (t) => {
  const f = fixture(t)
  const result = f.run({ PULL_STATUS: '1' })
  assert.equal(result.status, 0, result.stderr + result.stdout)
  const calls = f.calls()
  assert.ok(calls.includes('store:circuits pull'))
  assert.ok(calls.includes('build:circuits --preset all --committee all --skip-if-built'))
  assert.ok(calls.includes('generate:crypto-config'))
  assert.ok(calls.includes('build:circuits prepare-vk-commitments'))
  assert.ok(calls.includes('check:crypto-config --full'))
  assert.ok(calls.some((call) => call.startsWith('generate:verifiers --check')))
})

for (const failure of ['BUILD_STATUS', 'CATALOGUE_STATUS', 'VALIDATION_STATUS', 'VERIFIER_STATUS']) {
  test(`full-proof prebuild propagates ${failure} instead of repairing committed expectations`, (t) => {
    const f = fixture(t)
    const result = f.run({ ...(failure === 'BUILD_STATUS' ? { PULL_STATUS: '1' } : {}), [failure]: '17' })
    assert.equal(result.status, 17, result.stderr + result.stdout)
    assert.ok(!f.calls().some((call) => call.includes('sync-vk-commitments') || call.includes('--write')))
    assert.ok(!f.calls().some((call) => call.startsWith('store:circuits checksums')))
  })
}
