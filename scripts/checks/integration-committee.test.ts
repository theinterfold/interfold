// SPDX-License-Identifier: LGPL-3.0-only

import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { test } from 'node:test'

test('integration committee checks evaluate derived selections and still reject mismatched deployments', (t) => {
  const root = fileURLToPath(new URL('../..', import.meta.url))
  const temp = mkdtempSync(join(tmpdir(), 'interfold-integration-committee-'))
  t.after(() => rmSync(temp, { recursive: true, force: true }))
  mkdirSync(join(temp, 'scripts'))
  const { packageManager } = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'))
  writeFileSync(join(temp, 'package.json'), JSON.stringify({ name: 'committee-fixture', type: 'module', packageManager }))
  symlinkSync(join(root, 'node_modules'), join(temp, 'node_modules'), 'dir')
  copyFileSync(join(root, 'packages/interfold-contracts/crypto-config.json'), join(temp, 'crypto-config.json'))
  const select = (name) =>
    writeFileSync(
      join(temp, 'scripts/utils.ts'),
      `
import config from '../crypto-config.json';
const ACTIVE_BFV_CONFIG = config.committees.find(committee => committee.name === ${JSON.stringify(name)});
export const ACTIVE_BFV_COMMITTEE_SIZE = ACTIVE_BFV_CONFIG.committeeSize;
`,
    )
  const check = (zk, configured) =>
    spawnSync(
      'bash',
      [
        '-c',
        `
source "$1/tests/integration/lib/utils.sh"
jq() { printf '0x0000000000000000000000000000000000000001\\n'; }
cast() { case " $CONFIGURED " in *" $4 "*) printf '1\\n';; *) printf '0\\n';; esac; }
check_committee_sizes "$2" "$3"
`,
        'check',
        root,
        temp,
        zk,
      ],
      { env: { ...process.env, CONFIGURED: configured }, encoding: 'utf8' },
    )
  for (const [name, size] of [
    ['minimum', '0'],
    ['micro', '1'],
    ['small', '2'],
  ]) {
    select(name)
    const result = check('true', size)
    assert.equal(result.status, 0, result.stderr + result.stdout)
    assert.match(result.stdout, new RegExp(`configured committee sizes \\[${size}\\]`))
    assert.notEqual(check('true', '0 1 2').status, 0)
  }
  assert.equal(check('false', '0 1 2').status, 0)
  assert.notEqual(check('false', '0').status, 0)
  select('unknown')
  assert.notEqual(check('true', '0').status, 0)
})
