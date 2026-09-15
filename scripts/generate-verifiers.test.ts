// SPDX-License-Identifier: LGPL-3.0-only

import assert from 'node:assert/strict'
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { CIRCUIT_COMMITTEES, CIRCUIT_PRESETS } from './circuit-constants'
import { NoirCircuitBuilder } from './build-circuits'
import {
  assertExactVerifierInventory,
  expectedVerifierRelativePaths,
  onChainVerifierCircuits,
  prepareAllSupportedOutput,
  pruneUnsupportedVerifierDirs,
  unsupportedVerifierDirs,
  VerifierGenerator,
} from './generate-verifiers'

function verifierFixture(): { root: string; verifierDir: string } {
  const root = mkdtempSync(join(tmpdir(), 'interfold-verifiers-'))
  const verifierDir = join(root, 'packages', 'interfold-contracts', 'contracts', 'verifiers', 'bfv', 'honk')
  mkdirSync(verifierDir, { recursive: true })
  return { root, verifierDir }
}

test('defines the exact on-chain verifier inventory for supported pairs', () => {
  const paths = expectedVerifierRelativePaths()

  assert.equal(paths.length, 15)
  assert.equal(paths.filter((path) => path.endsWith('DkgAggregatorV2Verifier.sol')).length, 1)
  assert.equal(
    paths.some((path) => path.startsWith('secure-16384/micro/')),
    false,
  )
  assert.equal(
    paths.some((path) => path.startsWith('secure-16384/small/')),
    false,
  )
  assert.deepEqual(onChainVerifierCircuits(CIRCUIT_PRESETS.SECURE_16384, CIRCUIT_COMMITTEES.MINIMUM), [
    'dkg_aggregator',
    'decryption_aggregator',
    'dkg_aggregator_v2',
  ])
  assert.throws(() => onChainVerifierCircuits(CIRCUIT_PRESETS.SECURE_16384, CIRCUIT_COMMITTEES.MICRO), /Unsupported preset\/committee pair/)
})

test('checks the generated Solidity inventory exactly', () => {
  const fixture = verifierFixture()
  try {
    for (const path of expectedVerifierRelativePaths()) {
      const output = join(fixture.verifierDir, path)
      mkdirSync(dirname(output), { recursive: true })
      writeFileSync(output, '// verifier\n')
    }
    assert.doesNotThrow(() => assertExactVerifierInventory(fixture.root))

    const unexpected = join(fixture.verifierDir, 'secure-16384', 'small', 'DkgAggregatorVerifier.sol')
    mkdirSync(dirname(unexpected), { recursive: true })
    writeFileSync(unexpected, '// unsupported\n')
    assert.throws(() => assertExactVerifierInventory(fixture.root), /Unexpected: secure-16384\/small/)
  } finally {
    rmSync(fixture.root, { recursive: true, force: true })
  }
})

test('prunes only unsupported preset and committee directories', () => {
  const fixture = verifierFixture()
  try {
    const supported = join(fixture.verifierDir, 'secure-16384', 'minimum', 'DkgAggregatorVerifier.sol')
    const unsupported = join(fixture.verifierDir, 'secure-16384', 'small', 'DkgAggregatorVerifier.sol')
    for (const output of [supported, unsupported]) {
      mkdirSync(dirname(output), { recursive: true })
      writeFileSync(output, '// verifier\n')
    }

    assert.deepEqual(pruneUnsupportedVerifierDirs(fixture.root), ['secure-16384/small'])
    assert.equal(existsSync(supported), true)
    assert.equal(existsSync(unsupported), false)
  } finally {
    rmSync(fixture.root, { recursive: true, force: true })
  }
})

test('lists unsupported verifier directories without pruning them', () => {
  const fixture = verifierFixture()
  try {
    const unsupported = join(fixture.verifierDir, 'secure-16384', 'small', 'DkgAggregatorVerifier.sol')
    mkdirSync(dirname(unsupported), { recursive: true })
    writeFileSync(unsupported, '// unsupported\n')

    assert.deepEqual(unsupportedVerifierDirs(fixture.root), ['secure-16384/small'])
    assert.equal(existsSync(unsupported), true)
  } finally {
    rmSync(fixture.root, { recursive: true, force: true })
  }
})

test('leaves the active selector unchanged when a dist-backed check fails', async () => {
  const fixture = verifierFixture()
  try {
    const circuitDir = join(fixture.root, 'circuits', 'bin', 'recursive_aggregation', 'dkg_aggregator')
    const activePath = join(fixture.root, 'circuits', 'bin', '.active-preset.json')
    const selectorPath = join(fixture.root, 'circuits', 'lib', 'src', 'active_config.nr')
    const artifactDir = join(fixture.root, 'dist', 'circuits', 'insecure', 'minimum')
    const artifactCircuitDir = join(artifactDir, 'evm', 'recursive_aggregation', 'dkg_aggregator')
    mkdirSync(circuitDir, { recursive: true })
    mkdirSync(dirname(selectorPath), { recursive: true })
    mkdirSync(artifactCircuitDir, { recursive: true })
    writeFileSync(join(circuitDir, 'Nargo.toml'), 'name = "dkg_aggregator"\n')
    writeFileSync(activePath, '{"preset":"secure-16384","committee":"minimum"}\n')
    writeFileSync(selectorPath, 'user-owned selector\n')
    const sourceHash = new NoirCircuitBuilder(fixture.root, {
      preset: CIRCUIT_PRESETS.INSECURE_512,
      committee: CIRCUIT_COMMITTEES.MINIMUM,
    }).computeSourceHash(CIRCUIT_PRESETS.INSECURE_512, CIRCUIT_COMMITTEES.MINIMUM)
    const stampPath = join(artifactDir, '.build-stamp.json')
    writeFileSync(stampPath, `${JSON.stringify({ preset: 'insecure', committee: 'minimum', sourceHash: 'stale' })}\n`)
    writeFileSync(join(artifactCircuitDir, 'dkg_aggregator.json'), '{}\n')

    const generator = new VerifierGenerator(fixture.root, {
      groups: ['recursive_aggregation'],
      circuits: ['dkg_aggregator'],
      check: true,
      compile: false,
      preset: CIRCUIT_PRESETS.INSECURE_512,
      committee: CIRCUIT_COMMITTEES.MINIMUM,
      artifactDir,
    })
    Object.assign(generator, { checkTool: () => undefined })

    await assert.rejects(generator.generate(), /stale source hash/)
    writeFileSync(stampPath, `${JSON.stringify({ preset: 'insecure', committee: 'minimum', sourceHash })}\n`)
    await assert.rejects(generator.generate(), /generation error/)
    assert.equal(readFileSync(activePath, 'utf8'), '{"preset":"secure-16384","committee":"minimum"}\n')
    assert.equal(readFileSync(selectorPath, 'utf8'), 'user-owned selector\n')
    assert.equal(existsSync(join(circuitDir, 'target')), false)
  } finally {
    rmSync(fixture.root, { recursive: true, force: true })
  }
})

test('all-supported dry runs do not clean or prune verifier outputs', () => {
  const fixture = verifierFixture()
  try {
    const unsupported = join(fixture.verifierDir, 'secure-16384', 'small', 'DkgAggregatorVerifier.sol')
    mkdirSync(dirname(unsupported), { recursive: true })
    writeFileSync(unsupported, '// unsupported\n')

    prepareAllSupportedOutput(fixture.root, { clean: true, dryRun: true })

    assert.equal(existsSync(unsupported), true)
  } finally {
    rmSync(fixture.root, { recursive: true, force: true })
  }
})

test('all-supported clean removes the verifier root once before generation', () => {
  const fixture = verifierFixture()
  try {
    const existing = join(fixture.verifierDir, 'secure-8192', 'minimum', 'DkgAggregatorVerifier.sol')
    mkdirSync(dirname(existing), { recursive: true })
    writeFileSync(existing, '// old verifier\n')

    prepareAllSupportedOutput(fixture.root, { clean: true })

    assert.equal(existsSync(fixture.verifierDir), false)
  } finally {
    rmSync(fixture.root, { recursive: true, force: true })
  }
})
