// SPDX-License-Identifier: LGPL-3.0-only

import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

for (const scenario of [
  { name: 'runs the library, decryption aggregator, and DKG matrix', failedPackage: '', status: 0 },
  { name: 'propagates a decryption aggregator failure', failedPackage: 'decryption_aggregator', status: 17 },
  { name: 'restores the active configuration after a DKG failure', failedPackage: 'dkg_aggregator', status: 17 },
]) {
  test(`Noir runner ${scenario.name}`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'interfold-noir-runner-')))
    t.after(() => rmSync(root, { recursive: true, force: true }))
    const packages = [
      'circuits/lib',
      'circuits/bin/recursive_aggregation/decryption_aggregator',
      'circuits/bin/recursive_aggregation/dkg_aggregator',
    ]
    const activeCommittee = join(root, 'circuits/lib/src/configs/committee/active.nr')
    const activePreset = join(root, 'circuits/lib/src/configs/default/mod.nr')
    for (const dir of ['scripts', 'fake-bin', 'circuits/lib/src/configs/committee', 'circuits/lib/src/configs/default', ...packages]) {
      mkdirSync(join(root, dir), { recursive: true })
    }
    const originalCommittee = 'use committee::minimum::config;\n'
    const originalPreset = 'use super::insecure::config;\n'
    writeFileSync(activeCommittee, originalCommittee)
    writeFileSync(activePreset, originalPreset)
    copyFileSync(join(__dirname, 'test-circuits.sh'), join(root, 'scripts/test-circuits.sh'))
    writeFileSync(
      join(root, 'fake-bin/nargo'),
      `#!${process.execPath}
const fs = require('node:fs');
const path = require('node:path');
const cwd = process.cwd();
const entry = { cwd };
if (cwd.endsWith('/dkg_aggregator')) {
  const committee = fs.readFileSync(path.join(process.env.FIXTURE_ROOT, 'circuits/lib/src/configs/committee/active.nr'), 'utf8');
  const preset = fs.readFileSync(path.join(process.env.FIXTURE_ROOT, 'circuits/lib/src/configs/default/mod.nr'), 'utf8');
  entry.committee = committee.match(/committee::(minimum|micro|small)/)?.[1];
  entry.preset = preset.match(/super::(insecure|secure)::/)?.[1];
}
fs.appendFileSync(process.env.RUN_LOG, JSON.stringify(entry) + '\\n');
if (process.env.FAILED_PACKAGE && cwd.endsWith('/' + process.env.FAILED_PACKAGE)) process.exit(17);
`,
      { mode: 0o755 },
    )
    const log = join(root, 'packages.log')
    const result = spawnSync('bash', [join(root, 'scripts/test-circuits.sh')], {
      cwd: root,
      env: {
        ...process.env,
        PATH: `${join(root, 'fake-bin')}:${process.env.PATH}`,
        FAILED_PACKAGE: scenario.failedPackage,
        FIXTURE_ROOT: root,
        RUN_LOG: log,
      },
      encoding: 'utf8',
      timeout: 5_000,
    })
    assert.equal(result.status, scenario.status, result.stderr)

    const calls = readFileSync(log, 'utf8').trim().split('\n').map(JSON.parse)
    const expectedPackages = scenario.failedPackage
      ? packages.slice(0, scenario.failedPackage === 'decryption_aggregator' ? 2 : 3)
      : [packages[0], packages[1], ...Array(6).fill(packages[2])]
    assert.deepEqual(
      calls.map((call) => call.cwd),
      expectedPackages.map((dir) => join(root, dir)),
    )

    if (scenario.status === 0) {
      assert.deepEqual(
        calls.slice(2).map(({ committee, preset }) => [committee, preset]),
        [
          ['minimum', 'insecure'],
          ['minimum', 'secure'],
          ['micro', 'insecure'],
          ['micro', 'secure'],
          ['small', 'insecure'],
          ['small', 'secure'],
        ],
      )
    } else {
      assert.doesNotMatch(result.stdout, /circuits tested successfully/)
    }
    assert.equal(readFileSync(activeCommittee, 'utf8'), originalCommittee)
    assert.equal(readFileSync(activePreset, 'utf8'), originalPreset)
  })
}
