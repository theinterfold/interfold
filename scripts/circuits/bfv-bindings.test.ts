// SPDX-License-Identifier: LGPL-3.0-only

import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import {
  copyFileSync,
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { test } from 'node:test'

import {
  BFV_ENCRYPTION_SCHEME_ID,
  BFV_PRESETS,
  CIRCUIT_DIMENSIONS,
  COMMITTEES,
  INTERFOLD_BFV_VERSION,
  SUPPORTED_BFV_BUILD_PAIRS,
  bfvPresetForParamSet,
} from '../../packages/interfold-contracts/bfv'
import { BFV_PARAMS } from '../../packages/interfold-contracts/scripts/protocol/constants'
import { syncSnapshot } from './crypto-config.mjs'

const root = resolve(__dirname, '../..')
const packageRoot = join(root, 'packages/interfold-contracts')
const requireContracts = createRequire(join(packageRoot, 'package.json'))
const { AbiCoder, id, keccak256 } = requireContracts('ethers')
const fixture = JSON.parse(readFileSync(join(root, 'crates/fhe-params/tests/fixtures/bfv_protocol.json'), 'utf8'))

test('generated parameters retain independent ABI and configuration-ID vectors', () => {
  assert.equal(BFV_ENCRYPTION_SCHEME_ID, fixture.encryptionSchemeId)
  assert.equal(INTERFOLD_BFV_VERSION, fixture.currentCircuitVersion)
  for (const vector of fixture.vectors.filter((vector: { preset: string | null }) => vector.preset !== null)) {
    const preset = bfvPresetForParamSet(vector.paramSet)
    assert.ok(preset)
    assert.equal(preset.configId, vector.cryptoConfigId)
    const p = preset.threshold
    const encoded = AbiCoder.defaultAbiCoder().encode(
      ['tuple(uint256,uint256,uint256[],string)'],
      [[p.degree, p.plaintextModulus, p.moduli, p.error1Variance]],
    )
    assert.equal(encoded, vector.encodedParameters)
    assert.equal(keccak256(encoded), vector.parameterHash)
    assert.equal(
      keccak256(
        AbiCoder.defaultAbiCoder().encode(
          ['bytes32', 'bytes32', 'bytes32'],
          [BFV_ENCRYPTION_SCHEME_ID, preset.paramSetHash, id(vector.circuitVersion)],
        ),
      ),
      vector.cryptoConfigId,
    )
  }
  assert.equal(bfvPresetForParamSet(1), undefined)
  assert.equal(bfvPresetForParamSet(256), undefined)
  assert.equal(bfvPresetForParamSet('0' as unknown as number), undefined)
  assert.deepEqual(BFV_PARAMS.insecure64, BFV_PRESETS['insecure-64'].threshold)
  assert.deepEqual(BFV_PARAMS.secure8192, BFV_PRESETS['secure-8192'].threshold)
  assert.deepEqual(Object.keys(BFV_PARAMS.insecure64), ['degree', 'plaintextModulus', 'moduli', 'error1Variance'])
})

test('the snapshot check preserves the checked source and its modification time', () => {
  const binding = join(packageRoot, 'crypto-config.json')
  const before = readFileSync(binding)
  const mtime = statSync(binding).mtimeMs
  execFileSync(process.execPath, ['scripts/circuits/crypto-config.mjs', '--check'], { cwd: root, stdio: 'pipe' })
  assert.deepEqual(readFileSync(binding), before)
  assert.equal(statSync(binding).mtimeMs, mtime)
})

test('snapshot refresh is deterministic and checks never repair missing or stale data', () => {
  const temp = mkdtempSync(join(tmpdir(), 'interfold-crypto-config-'))
  try {
    const path = join(temp, 'crypto-config.json')
    const metadata = JSON.parse(readFileSync(join(packageRoot, 'crypto-config.json'), 'utf8'))
    assert.throws(() => syncSnapshot(path, metadata, true), /missing or stale/)
    assert.equal(existsSync(path), false)
    syncSnapshot(path, metadata)
    const generated = readFileSync(path)
    const mtime = statSync(path).mtimeMs
    syncSnapshot(path, metadata)
    syncSnapshot(path, metadata, true)
    assert.equal(statSync(path).mtimeMs, mtime)
    metadata.zk.messageCoeffsCount += 1
    assert.throws(() => syncSnapshot(path, metadata, true), /missing or stale/)
    assert.deepEqual(readFileSync(path), generated)
    assert.equal(statSync(path).mtimeMs, mtime)
    syncSnapshot(path, metadata)
    assert.deepEqual(JSON.parse(readFileSync(path, 'utf8')), metadata)
  } finally {
    rmSync(temp, { recursive: true, force: true })
  }
})

test('a failed native export preserves the snapshot and its exit status', () => {
  const temp = mkdtempSync(join(tmpdir(), 'interfold-crypto-export-'))
  try {
    mkdirSync(join(temp, 'scripts/circuits'), { recursive: true })
    mkdirSync(join(temp, 'packages/interfold-contracts'), { recursive: true })
    mkdirSync(join(temp, 'bin'))
    const script = join(temp, 'scripts/circuits/crypto-config.mjs')
    const snapshot = join(temp, 'packages/interfold-contracts/crypto-config.json')
    copyFileSync(join(root, 'scripts/circuits/crypto-config.mjs'), script)
    writeFileSync(snapshot, 'existing snapshot')
    writeFileSync(join(temp, 'bin/cargo'), '#!/bin/sh\nexit 17\n', { mode: 0o755 })
    const result = spawnSync(process.execPath, [script], { env: { ...process.env, PATH: join(temp, 'bin') } })
    assert.equal(result.status, 17)
    assert.equal(readFileSync(snapshot, 'utf8'), 'existing snapshot')
  } finally {
    rmSync(temp, { recursive: true, force: true })
  }
})

test('bindings retain each owner-provided parameter family, search recipe, and circuit dimension', () => {
  const metadata = JSON.parse(execFileSync('pnpm', ['--silent', 'build:circuits', 'export-config'], { cwd: root, encoding: 'utf8' }))
  assert.deepEqual(JSON.parse(readFileSync(join(packageRoot, 'crypto-config.json'), 'utf8')), metadata)
  for (const record of metadata.bfv.presets) {
    const preset = BFV_PRESETS[record.preset as keyof typeof BFV_PRESETS]
    for (const family of ['threshold', 'dkg'] as const) {
      assert.equal(preset[family].degree.toString(), record[family].degree)
      assert.equal(preset[family].plaintextModulus.toString(), record[family].plaintextModulus)
      assert.deepEqual(
        preset[family].moduli.map((value) => value.toString()),
        record[family].moduli,
      )
      assert.equal(preset[family].error1Variance, record[family].error1Variance)
    }
    assert.deepEqual(preset.search, record.search)
  }
  assert.deepEqual(CIRCUIT_DIMENSIONS, metadata.zk)
  assert.deepEqual(Object.values(COMMITTEES), metadata.committees)
  assert.deepEqual(SUPPORTED_BFV_BUILD_PAIRS, metadata.buildPairs)
})

test('the dependency-free committee gate rejects binding drift and independent consumer IDs', () => {
  const temp = mkdtempSync(join(tmpdir(), 'interfold-committee-check-'))
  try {
    const files = [
      'scripts/checks/committee.sh',
      'packages/interfold-contracts/crypto-config.json',
      'packages/interfold-contracts/scripts/protocol/constants.ts',
      'packages/interfold-contracts/scripts/utils.ts',
      'packages/interfold-contracts/contracts/lib/BfvProtocol.sol',
      'packages/interfold-contracts/tasks/interfold.ts',
      'packages/interfold-sdk/src/utils.ts',
      'crates/fhe-params/src/constants.rs',
      'crates/committee/src/lib.rs',
      'crates/evm-helpers/src/contracts.rs',
      'circuits/lib/src/configs/committee/active.nr',
      ...['minimum', 'micro', 'small'].map((committee) => `circuits/lib/src/configs/committee/${committee}/mod.nr`),
      ...['insecure', 'secure'].map((preset) => `circuits/lib/src/configs/${preset}/threshold.nr`),
    ]
    for (const file of files) {
      mkdirSync(dirname(join(temp, file)), { recursive: true })
      copyFileSync(join(root, file), join(temp, file))
    }
    mkdirSync(join(temp, 'bin'))
    symlinkSync(process.execPath, join(temp, 'bin/node'))
    const check = () =>
      execFileSync('/bin/bash', [join(temp, 'scripts/checks/committee.sh')], {
        cwd: temp,
        env: { ...process.env, PATH: `${join(temp, 'bin')}:/usr/bin:/bin` },
        stdio: 'pipe',
      })
    check()
    const binding = join(temp, 'packages/interfold-contracts/crypto-config.json')
    const source = readFileSync(binding, 'utf8')
    const stale = JSON.parse(source)
    stale.bfv.presets[0].threshold.degree = '1'
    writeFileSync(binding, JSON.stringify(stale))
    assert.throws(check)
    writeFileSync(binding, source)
    stale.bfv.presets[0].threshold.degree = BFV_PRESETS['insecure-64'].threshold.degree.toString()
    stale.bfv.presets[0].cryptoConfigId = `0x${'00'.repeat(32)}`
    writeFileSync(binding, JSON.stringify(stale))
    assert.throws(check)
    writeFileSync(binding, source)
    const sdk = join(temp, 'packages/interfold-sdk/src/utils.ts')
    writeFileSync(sdk, `${readFileSync(sdk, 'utf8')}\nconst copiedId = ${JSON.stringify(fixture.vectors[0].cryptoConfigId)};\n`)
    assert.throws(check)
    copyFileSync(join(root, 'packages/interfold-sdk/src/utils.ts'), sdk)
    const task = join(temp, 'packages/interfold-contracts/tasks/interfold.ts')
    writeFileSync(task, readFileSync(task, 'utf8').replace('../bfv.js', '../wrong-bfv.js'))
    assert.throws(check)
  } finally {
    rmSync(temp, { recursive: true, force: true })
  }
})

test('the packed BFV subpath supports browser builds, ESM, CJS, and both declaration formats', () => {
  const temp = mkdtempSync(join(tmpdir(), 'interfold-bfv-package-'))
  try {
    // Match compile:ts: emit the adapter first, then bundle JSON for both public and relative imports.
    const tsconfig = join(temp, 'tsconfig.bfv.json')
    writeFileSync(tsconfig, JSON.stringify({ extends: join(packageRoot, 'tsconfig.json'), include: [join(packageRoot, 'bfv.ts')] }))
    execFileSync('pnpm', ['exec', 'tsc', '--project', tsconfig], { cwd: packageRoot, stdio: 'pipe' })
    execFileSync('pnpm', ['build:bfv'], { cwd: packageRoot, stdio: 'pipe' })
    execFileSync('pnpm', ['pack', '--pack-destination', temp], { cwd: packageRoot, stdio: 'pipe' })
    const archive = readdirSync(temp).find((file) => file.endsWith('.tgz'))
    assert.ok(archive)
    const installed = join(temp, 'node_modules/@interfold/contracts')
    mkdirSync(installed, { recursive: true })
    execFileSync('tar', ['-xzf', join(temp, archive), '--strip-components=1', '-C', installed])
    const secure = fixture.vectors.find((v: { name: string }) => v.name === 'current-secure')
    const check = `if (bfv.bfvPresetForParamSet(${secure.paramSet}).configId !== ${JSON.stringify(secure.cryptoConfigId)}) throw new Error('wrong ID'); if (typeof bfv.bfvPresetForParamSet(${secure.paramSet}).threshold.degree !== 'bigint') throw new Error('lost integer type');`
    execFileSync(process.execPath, ['--input-type=module', '-e', `import * as bfv from '@interfold/contracts/bfv'; ${check}`], {
      cwd: temp,
      stdio: 'pipe',
    })
    execFileSync(process.execPath, ['-e', `const bfv = require('@interfold/contracts/bfv'); ${check}`], { cwd: temp, stdio: 'pipe' })
    const consumer = `const degree: bigint = bfv.bfvPresetForParamSet(${secure.paramSet})!.threshold.degree; const id: \`0x\${string}\` | undefined = bfv.bfvPresetForParamSet(${secure.paramSet})?.configId; void degree; void id;`
    writeFileSync(join(temp, 'consumer.mts'), `import * as bfv from '@interfold/contracts/bfv'; ${consumer}`)
    writeFileSync(join(temp, 'consumer.cts'), `import bfv = require('@interfold/contracts/bfv'); ${consumer}`)
    writeFileSync(
      join(temp, 'tsconfig.json'),
      JSON.stringify({
        compilerOptions: { target: 'ES2022', module: 'NodeNext', moduleResolution: 'NodeNext', strict: true, types: [], noEmit: true },
        files: ['consumer.mts', 'consumer.cts'],
      }),
    )
    execFileSync('pnpm', ['exec', 'tsc', '--project', join(temp, 'tsconfig.json')], { cwd: packageRoot, stdio: 'pipe' })
  } finally {
    rmSync(temp, { recursive: true, force: true })
  }
})
