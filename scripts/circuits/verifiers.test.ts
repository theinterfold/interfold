// SPDX-License-Identifier: LGPL-3.0-only

import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import test from 'node:test'
import {
  assertExactVerifierInventory,
  expectedVerifierRelativePaths,
  onChainVerifierCircuits,
  prepareAllSupportedOutput,
  pruneUnsupportedVerifierDirs,
  unsupportedVerifierDirs,
  VerifierGenerator,
} from './verifiers'
import { CIRCUIT_COMMITTEES, CIRCUIT_PRESETS } from './constants'

test('secure-16384 micro has the l-BFV verifier route', () => {
  assert.deepEqual(onChainVerifierCircuits(CIRCUIT_PRESETS.SECURE_16384, CIRCUIT_COMMITTEES.MICRO), [
    'dkg_aggregator',
    'decryption_aggregator',
    'dkg_aggregator_v2',
  ])
})

test('retains the exact l-BFV and trBFV on-chain verifier matrix', () => {
  const paths = expectedVerifierRelativePaths()
  assert.equal(paths.length, 24)
  assert.equal(paths.filter((path) => path.endsWith('DkgAggregatorV2Verifier.sol')).length, 6)
  assert.ok(paths.some((path) => path.startsWith('secure-16384/small/')))
  assert.ok(paths.some((path) => path.startsWith('secure-16384/micro/')))
  for (const preset of [CIRCUIT_PRESETS.INSECURE, CIRCUIT_PRESETS.SECURE_16384]) {
    assert.deepEqual(onChainVerifierCircuits(preset, CIRCUIT_COMMITTEES.MINIMUM), [
      'dkg_aggregator',
      'decryption_aggregator',
      'dkg_aggregator_v2',
    ])
  }
  assert.throws(() => onChainVerifierCircuits('unsupported' as never, CIRCUIT_COMMITTEES.MICRO), /Unsupported preset\/committee pair/)
})

test('verifier inventory is exact and unknown directories are not pruned', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'interfold-verifier-inventory-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const directory = join(root, 'packages/interfold-contracts/contracts/verifiers/bfv/honk')
  for (const path of expectedVerifierRelativePaths()) {
    mkdirSync(dirname(join(directory, path)), { recursive: true })
    writeFileSync(join(directory, path), '// synthetic verifier\n')
  }
  assertExactVerifierInventory(root)
  const unsupported = join(directory, 'secure-16384/unsupported/DkgAggregatorVerifier.sol')
  mkdirSync(dirname(unsupported), { recursive: true })
  writeFileSync(unsupported, '// unsupported\n')
  assert.throws(() => assertExactVerifierInventory(root), /Unexpected: secure-16384\/unsupported/)
  assert.deepEqual(unsupportedVerifierDirs(root), [])
  prepareAllSupportedOutput(root, { clean: true, dryRun: true })
  assert.ok(existsSync(unsupported))
  assert.deepEqual(pruneUnsupportedVerifierDirs(root), [])
  assert.ok(existsSync(unsupported))
  rmSync(unsupported)
  assertExactVerifierInventory(root)
})

test('disabled known pairs are pruned only outside dry-run mode', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'interfold-disabled-verifier-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  for (const name of ['constants.ts', 'verifiers.ts']) copyFileSync(join(__dirname, name), join(root, name))
  const pairs: string[][] = JSON.parse(readFileSync(join(__dirname, 'build-pairs.json'), 'utf8'))
  writeFileSync(
    join(root, 'build-pairs.json'),
    JSON.stringify(pairs.filter(([preset, committee]) => preset !== 'secure-16384' || committee !== 'micro')),
  )
  const removed = JSON.parse(
    execFileSync(
      'pnpm',
      [
        'tsx',
        '-e',
        `
    const policy = require(process.argv[1]);
    const root = process.argv[2];
    const fs = require('node:fs');
    const dir = root + '/packages/interfold-contracts/contracts/verifiers/bfv/honk/secure-16384/micro';
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(dir + '/DkgAggregatorV2Verifier.sol', '// synthetic');
    policy.prepareAllSupportedOutput(root, { clean: true, dryRun: true });
    if (!fs.existsSync(dir)) throw new Error('dry-run removed the pair');
    const removed = policy.pruneUnsupportedVerifierDirs(root);
    if (fs.existsSync(dir)) throw new Error('disabled pair was retained');
    console.log(JSON.stringify(removed));
  `,
        join(root, 'verifiers.ts'),
        root,
      ],
      { encoding: 'utf8' },
    ),
  )
  assert.deepEqual(removed, ['secure-16384/micro'])
})

// `check:verifiers` must fail when a requested circuit is not discovered, instead of checking less.
test('verifier generation rejects a requested circuit it cannot find', async (t) => {
  const root = fixture(t)
  const generator = new VerifierGenerator(root, { dryRun: true, circuits: ['dkg_aggregator', 'no_such_circuit'] })
  await assert.rejects(generator.generate(), /Cannot find requested circuits: no_such_circuit/)
})

// Exercise the existing public generation boundary with synthetic bb output, never real keys/proofs.
function fixture(t: { after: (fn: () => void) => void }): string {
  const root = mkdtempSync(join(tmpdir(), 'interfold-verifier-transform-'))
  const oldPath = process.env.PATH
  t.after(() => {
    process.env.PATH = oldPath
    rmSync(root, { recursive: true, force: true })
  })
  const write = (path: string, text: string, mode = 0o644) => {
    mkdirSync(dirname(join(root, path)), { recursive: true })
    writeFileSync(join(root, path), text, { mode })
  }
  write('bin/nargo', '#!/bin/sh\necho fixture\n', 0o755)
  write(
    'bin/bb',
    `#!/usr/bin/env node
const fs = require('node:fs')
const args = process.argv.slice(2)
if (args[0] === '--version') console.log('fixture')
else if (args[0] === 'write_solidity_verifier') fs.copyFileSync(${JSON.stringify(join(root, 'raw.sol'))}, args[args.indexOf('-o') + 1])
else process.exit(1)
`,
    0o755,
  )
  process.env.PATH = `${root}/bin:${resolve(__dirname, '../../node_modules/.bin')}:${oldPath}`
  write('circuits/bin/.active-preset.json', '{"preset":"insecure","committee":"minimum"}')
  write('dist/circuits/insecure/minimum/.build-stamp.json', '{"preset":"insecure","committee":"minimum","sourceHash":"fixture-source"}')
  write('circuits/bin/recursive_aggregation/dkg_aggregator/Nargo.toml', '[package]\nname = "dkg_aggregator"\n')
  write('circuits/bin/recursive_aggregation/dkg_aggregator/target/dkg_aggregator.json', '{}')
  write('circuits/bin/recursive_aggregation/dkg_aggregator/target/dkg_aggregator.vk', 'synthetic fixture, not a key')
  const packageManager = JSON.parse(readFileSync(resolve(__dirname, '../../package.json'), 'utf8')).packageManager
  write('package.json', JSON.stringify({ private: true, packageManager, scripts: { 'build:circuits': 'node source-hash.cjs' } }))
  write('source-hash.cjs', 'console.log("fixture-source")')
  write('packages/interfold-contracts/package.json', JSON.stringify({ private: true }))
  mkdirSync(join(root, 'packages/interfold-contracts'), { recursive: true })
  symlinkSync(resolve(__dirname, '../../node_modules'), join(root, 'node_modules'))
  copyFileSync(
    resolve(__dirname, '../../packages/interfold-contracts/.prettierrc.yml'),
    join(root, 'packages/interfold-contracts/.prettierrc.yml'),
  )
  write(
    'raw.sol',
    `// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.27;
library Errors {
    error ConsistencyCheckFailed();
}
library FrLib {
    bytes4 internal constant FRLIB_MODEXP_FAILED_SELECTOR = 0xf8d61709;
}
abstract contract BaseZKHonkVerifier {
    constructor(uint256 _N, uint256 _logN, uint256 _vkHash, uint256 _numPublicInputs) {
    }
    function verify() public view {}
}
contract HonkVerifier is BaseZKHonkVerifier(N, LOG_N, VK_HASH, NUMBER_OF_PUBLIC_INPUTS) {
}
`,
  )
  return root
}

test('verifier write/check retain selector correction, VK validation, naming and formatted output', async (t) => {
  const root = fixture(t)
  const options = { compile: false, noCleanTargets: true, circuits: ['dkg_aggregator'] }
  await new VerifierGenerator(root, options).generate()
  const path = join(root, 'packages/interfold-contracts/contracts/verifiers/bfv/honk/DkgAggregatorVerifier.sol')
  const output = readFileSync(path, 'utf8')
  assert.match(output, /SPDX-License-Identifier: LGPL-3.0-only/)
  assert.match(output, /contract DkgAggregatorVerifier/)
  assert.match(output, /FRLIB_MODEXP_FAILED_SELECTOR = 0x1f7ec5f0/)
  assert.doesNotMatch(output, /0xf8d61709/)
  assert.match(output, /validateVerificationKey\(HonkVerificationKey.loadVerificationKey\(\)\)/)
  for (const parameter of ['$N', '$LOG_N', '$NUM_PUBLIC_INPUTS']) assert.ok(output.includes(parameter))
  await new VerifierGenerator(root, { ...options, check: true }).generate()
  assert.equal(readFileSync(path, 'utf8'), output)
})
