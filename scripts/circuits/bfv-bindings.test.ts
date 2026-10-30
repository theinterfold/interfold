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
  DECRYPTION_AGGREGATOR_LAYOUT,
  DECRYPTION_INPUT_INDICES,
  COMMITTEES,
  INTERFOLD_BFV_VERSION,
  SUPPORTED_BFV_BUILD_PAIRS,
  bfvPresetForParamSet,
  decryptionAggregatorLayout,
} from '../../packages/interfold-contracts/bfv'
import { BFV_PARAMS } from '../../packages/interfold-contracts/scripts/protocol/constants'
import {
  ACTIVE_BFV_PRESET,
  ACTIVE_BFV_COMMITTEE,
  ACTIVE_BFV_PARAM_SET,
  ACTIVE_BFV_COMMITTEE_SIZE,
  ACTIVE_BFV_COMMITTEE_N,
  BFV_DKG_H,
  BFV_THRESHOLD_T,
  MAINNET_BFV_CONFIGS,
  TESTNET_BFV_CONFIGS,
  PRODUCTION_BFV_CONFIG,
  TESTNET_BFV_CONFIG,
  activeBfvConfigForChain,
} from '../../packages/interfold-contracts/scripts/utils'
import { COMMITTEE_PARAMS } from './constants'
import { syncSnapshot } from './crypto-config.mjs'

const root = resolve(__dirname, '../..')
const packageRoot = join(root, 'packages/interfold-contracts')
const requireContracts = createRequire(join(packageRoot, 'package.json'))
const { AbiCoder, id, keccak256 } = requireContracts('ethers')
const fixture = JSON.parse(readFileSync(join(root, 'crates/fhe-params/tests/fixtures/bfv_protocol.json'), 'utf8'))

test('deployment routes retain chain policy and order while projecting owner metadata', () => {
  assert.deepEqual(
    TESTNET_BFV_CONFIGS.map(({ preset, committee }) => [preset, committee]),
    [
      ['insecure-64', 'minimum'],
      ['insecure-64', 'micro'],
      ['insecure-64', 'small'],
      ['insecure-64', 'large'],
      ['secure-8192', 'minimum'],
      ['secure-8192', 'micro'],
      ['secure-8192', 'small'],
      ['secure-8192', 'large'],
    ],
  )
  assert.deepEqual(
    MAINNET_BFV_CONFIGS.map(({ preset, committee }) => [preset, committee]),
    [
      ['secure-8192', 'small'],
      ['secure-8192', 'micro'],
      ['secure-8192', 'minimum'],
    ],
  )
  for (const route of TESTNET_BFV_CONFIGS) {
    const preset = BFV_PRESETS[route.preset]
    const committee = COMMITTEES[route.committee]
    assert.deepEqual(route, {
      preset: route.preset,
      committee: route.committee,
      paramSet: preset.paramSet,
      paramSetHash: preset.paramSetHash,
      configId: preset.configId,
      committeeSize: committee.committeeSize,
      h: committee.h,
      t: committee.t,
      n: committee.n,
    })
    assert.deepEqual(COMMITTEE_PARAMS[route.committee], { n: committee.n, t: committee.t, h: committee.h })
  }
  for (const chain of [11155111, 31337, 1337]) assert.equal(activeBfvConfigForChain(chain), TESTNET_BFV_CONFIG)
  for (const chain of [1, 137]) assert.equal(activeBfvConfigForChain(chain), PRODUCTION_BFV_CONFIG)
  assert.equal(PRODUCTION_BFV_CONFIG, MAINNET_BFV_CONFIGS[0])
  assert.equal(TESTNET_BFV_CONFIG, TESTNET_BFV_CONFIGS[0])
  const selected = TESTNET_BFV_CONFIGS.find(({ preset, committee }) => preset === ACTIVE_BFV_PRESET && committee === ACTIVE_BFV_COMMITTEE)!
  assert.deepEqual(
    [ACTIVE_BFV_PARAM_SET, ACTIVE_BFV_COMMITTEE_SIZE, ACTIVE_BFV_COMMITTEE_N, BFV_DKG_H, BFV_THRESHOLD_T],
    [selected.paramSet, selected.committeeSize, selected.n, selected.h, selected.t],
  )
})

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

test('unsupported wrapper flags fail before invoking native tools', () => {
  const result = spawnSync(process.execPath, ['scripts/circuits/crypto-config.mjs', '--check', '--full', '--bindings-only'], {
    cwd: root,
    env: { ...process.env, PATH: '' },
    encoding: 'utf8',
  })
  assert.equal(result.status, 1)
  assert.match(result.stderr, /Usage:/)
  assert.doesNotMatch(result.stderr, /cargo/)
})

test('binding lookups reject missing preset, committee, and public-input names when loaded', () => {
  const temp = mkdtempSync(join(tmpdir(), 'interfold-bfv-lookups-'))
  try {
    copyFileSync(join(packageRoot, 'bfv.ts'), join(temp, 'bfv.ts'))
    const metadata = JSON.parse(readFileSync(join(packageRoot, 'crypto-config.json'), 'utf8'))
    for (const [key, field, name, message] of [
      ['presets', 'preset', 'insecure-64', /Missing BFV preset/],
      ['committees', 'name', 'minimum', /Missing committee/],
      ['publicInputs', 'name', 'domain_hi', /Missing decryption public input/],
    ] as const) {
      const changed = structuredClone(metadata)
      const owner = key === 'presets' ? changed.bfv : key === 'publicInputs' ? changed.zk.decryptionAggregator : changed
      owner[key] = owner[key].filter((record) => record[field] !== name)
      writeFileSync(join(temp, 'crypto-config.json'), JSON.stringify(changed))
      const result = spawnSync('pnpm', ['exec', 'tsx', '-e', `require(${JSON.stringify(join(temp, 'bfv.ts'))})`], {
        cwd: root,
        encoding: 'utf8',
      })
      assert.notEqual(result.status, 0)
      assert.match(result.stderr, message)
    }
  } finally {
    rmSync(temp, { recursive: true, force: true })
  }
})

test('the aggregate source check fails without Noir instead of using the lightweight fallback', () => {
  const temp = mkdtempSync(join(tmpdir(), 'interfold-source-tools-'))
  const snapshot = join(packageRoot, 'crypto-config.json')
  const before = readFileSync(snapshot)
  const mtime = statSync(snapshot).mtimeMs
  try {
    for (const tool of ['cargo', 'rustc']) {
      const binary = execFileSync('rustup', ['which', tool], { cwd: root, encoding: 'utf8' }).trim()
      symlinkSync(binary, join(temp, tool))
    }
    symlinkSync(process.execPath, join(temp, 'node'))
    const result = spawnSync(process.execPath, ['scripts/circuits/crypto-config.mjs', '--check', '--sources'], {
      cwd: root,
      env: { ...process.env, PATH: `${temp}:/usr/bin:/bin` },
      encoding: 'utf8',
    })
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /nargo/)
    assert.deepEqual(readFileSync(snapshot), before)
    assert.equal(statSync(snapshot).mtimeMs, mtime)
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
  const { decryptionAggregator, ...dimensions } = metadata.zk
  assert.deepEqual(CIRCUIT_DIMENSIONS, dimensions)
  assert.deepEqual(DECRYPTION_AGGREGATOR_LAYOUT, decryptionAggregator)
  assert.deepEqual(Object.values(COMMITTEES), metadata.committees)
  assert.deepEqual(SUPPORTED_BFV_BUILD_PAIRS, metadata.buildPairs)
})

test('decryption layout preserves independent application counts, offsets, and the non-preset threshold domain', () => {
  for (const [threshold, offsets] of [
    [1, [8, 10, 12, 14, 64]],
    [4, [8, 13, 18, 23, 73]],
    [9, [8, 18, 28, 38, 88]],
    [2, [8, 11, 14, 17, 67]],
  ] as const) {
    const layout = decryptionAggregatorLayout(threshold)
    assert.deepEqual([layout.partyIdOffset, layout.skOffset, layout.esmOffset, layout.messageOffset, layout.publicInputsLength], offsets)
  }
  assert.deepEqual(DECRYPTION_INPUT_INDICES, {
    c6_fold_key_hash: 0,
    c7_key_hash: 1,
    committee_hash_hi: 2,
    committee_hash_lo: 3,
    domain_hi: 4,
    domain_lo: 5,
    ciphertext_commitment: 6,
  })
})

test('the dependency-free committee gate compares binding values, not consumer implementation text', () => {
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
      'crates/evm/client/src/contracts.rs',
      'circuits/lib/src/configs/committee/active.nr',
      ...['minimum', 'micro', 'small', 'large'].map((committee) => `circuits/lib/src/configs/committee/${committee}/mod.nr`),
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
    const utils = join(temp, 'packages/interfold-contracts/scripts/utils.ts')
    const originalUtils = readFileSync(utils, 'utf8')
    writeFileSync(utils, `${originalUtils}\nconst unrelatedHash = "0x${'12'.repeat(32)}";\n`)
    check()
    writeFileSync(utils, originalUtils)
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
    for (const committee of ['minimum', 'micro', 'small', 'large']) {
      const changed = JSON.parse(source)
      changed.committees.find((record) => record.name === committee).h += 1
      writeFileSync(binding, JSON.stringify(changed))
      assert.throws(check)
    }
  } finally {
    rmSync(temp, { recursive: true, force: true })
  }
})

test('the packed BFV subpath builds browser-targeted bundles, ESM, CJS, and declarations in isolation', () => {
  const temp = mkdtempSync(join(tmpdir(), 'interfold-bfv-package-'))
  try {
    // Exercise the real package commands without changing the checkout's dist/ or needing Rust.
    const staged = join(temp, 'source')
    mkdirSync(staged)
    for (const file of ['package.json', 'bfv.ts', 'crypto-config.json']) copyFileSync(join(packageRoot, file), join(staged, file))
    symlinkSync(join(packageRoot, 'node_modules'), join(staged, 'node_modules'), 'dir')
    const tsconfig = join(staged, 'tsconfig.json')
    writeFileSync(
      tsconfig,
      JSON.stringify({ ...JSON.parse(readFileSync(join(packageRoot, 'tsconfig.json'), 'utf8')), include: ['bfv.ts'] }),
    )
    execFileSync('pnpm', ['exec', 'tsc', '--project', tsconfig], { cwd: staged, stdio: 'pipe' })
    execFileSync('pnpm', ['build:bfv'], { cwd: staged, stdio: 'pipe' })
    execFileSync('pnpm', ['pack', '--pack-destination', temp], { cwd: staged, stdio: 'pipe' })
    const archive = readdirSync(temp).find((file) => file.endsWith('.tgz'))
    assert.ok(archive)
    const installed = join(temp, 'node_modules/@interfold/contracts')
    mkdirSync(installed, { recursive: true })
    execFileSync('tar', ['-xzf', join(temp, archive), '--strip-components=1', '-C', installed])
    const secure = fixture.vectors.find((v: { name: string }) => v.name === 'current-secure')
    const check = `if (bfv.bfvPresetForParamSet(${secure.paramSet}).configId !== ${JSON.stringify(secure.cryptoConfigId)}) throw new Error('wrong ID'); if (typeof bfv.bfvPresetForParamSet(${secure.paramSet}).threshold.degree !== 'bigint') throw new Error('lost integer type'); if (bfv.decryptionAggregatorLayout(4).publicInputsLength !== 73) throw new Error('wrong layout');`
    execFileSync(process.execPath, ['--input-type=module', '-e', `import * as bfv from '@interfold/contracts/bfv'; ${check}`], {
      cwd: temp,
      stdio: 'pipe',
    })
    execFileSync(process.execPath, ['-e', `const bfv = require('@interfold/contracts/bfv'); ${check}`], { cwd: temp, stdio: 'pipe' })
    const consumer = `const degree: bigint = bfv.bfvPresetForParamSet(${secure.paramSet})!.threshold.degree; const id: \`0x\${string}\` | undefined = bfv.bfvPresetForParamSet(${secure.paramSet})?.configId; void degree; void id;
// @ts-expect-error unknown preset keys are not supported
bfv.BFV_PRESETS.missing;
// @ts-expect-error unknown committee keys are not supported
bfv.COMMITTEES.missing;
// @ts-expect-error public-input names are checked
bfv.DECRYPTION_INPUT_INDICES.domain_hii;
`
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
