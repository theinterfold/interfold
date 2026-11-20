// SPDX-License-Identifier: LGPL-3.0-only

import assert from 'node:assert/strict'
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, relative, resolve } from 'node:path'
import test from 'node:test'
import { VerifierGenerator } from './verifiers'
import { verifySynchronizedPublication } from './verify-sync-publication'

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
  const oldBb = process.env.E3_CUSTOM_BB
  delete process.env.E3_CUSTOM_BB
  t.after(() => {
    process.env.PATH = oldPath
    if (oldBb === undefined) delete process.env.E3_CUSTOM_BB
    else process.env.E3_CUSTOM_BB = oldBb
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
  write('circuits/bin/.active-preset.json', '{"preset":"insecure-64","committee":"minimum"}')
  write('dist/circuits/insecure-64/minimum/.build-stamp.json', '{"preset":"insecure-64","committee":"minimum"}')
  write('circuits/bin/recursive_aggregation/dkg_aggregator/Nargo.toml', '[package]\nname = "dkg_aggregator"\n')
  write('circuits/bin/recursive_aggregation/dkg_aggregator/target/dkg_aggregator.json', '{}')
  write('circuits/bin/recursive_aggregation/dkg_aggregator/target/dkg_aggregator.vk', 'synthetic fixture, not a key')
  const packageManager = JSON.parse(readFileSync(resolve(__dirname, '../../package.json'), 'utf8')).packageManager
  write('package.json', JSON.stringify({ private: true, packageManager }))
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

test('sync qualification renders only the explicit VK and propagates the prepared contract runner status', (t) => {
  const root = fixture(t)
  const prepared = join(root, 'temporary publication')
  mkdirSync(prepared)
  const vk = join(prepared, 'explicit.vk')
  writeFileSync(vk, 'synthetic qualification key')
  const input = join(prepared, 'publication.json')
  writeFileSync(input, JSON.stringify({ vk }))
  const canonical = join(root, 'packages/interfold-contracts/contracts/verifiers/bfv/honk/DkgAggregatorVerifier.sol')
  mkdirSync(dirname(canonical), { recursive: true })
  writeFileSync(canonical, 'untouched canonical verifier')
  const renderer = `#!/usr/bin/env node
const fs = require('node:fs')
const args = process.argv.slice(2)
require('node:assert/strict').deepEqual(args.slice(0, 3), ['write_solidity_verifier', '-k', ${JSON.stringify(vk)}])
fs.copyFileSync(${JSON.stringify(join(root, 'raw.sol'))}, args[args.indexOf('-o') + 1])
`
  writeFileSync(join(root, 'bin/bb'), renderer, { mode: 0o755 })
  const customBb = join(root, 'temporary publication/bb-6.0.0')
  writeFileSync(customBb, renderer, { mode: 0o755 })
  writeFileSync(
    join(root, 'bin/pnpm'),
    `#!/usr/bin/env node
const fs = require('node:fs')
const args = process.argv.slice(2)
if (args[1] === 'prettier') process.stdout.write(fs.readFileSync(0, 'utf8'))
else {
  fs.writeFileSync(${JSON.stringify(join(root, 'runner.json'))}, JSON.stringify({
    args, cwd: process.cwd(),
    fixture: process.env.E3_SYNC_PUBLICATION_FIXTURE,
    source: process.env.E3_SYNC_PUBLICATION_VERIFIER_SOURCE,
  }))
  process.exit(Number(fs.readFileSync(${JSON.stringify(join(root, 'status'))}, 'utf8')))
}
`,
    { mode: 0o755 },
  )
  for (const selected of [undefined, 'bb', customBb, relative(process.cwd(), customBb)]) {
    if (selected !== undefined) {
      process.env.E3_CUSTOM_BB = selected
    }
    if (selected !== undefined && selected !== 'bb') {
      // A custom executable must win over a different bb on PATH, even with a nonstandard name.
      writeFileSync(join(root, 'bin/bb'), '#!/bin/sh\nexit 97\n', { mode: 0o755 })
    }
    for (const status of [0, 23]) {
      writeFileSync(join(root, 'status'), String(status))
      assert.equal(verifySynchronizedPublication(root, input), status)
      assert.deepEqual(JSON.parse(readFileSync(join(root, 'runner.json'), 'utf8')), {
        args: [
          'exec',
          'hardhat',
          '--config',
          'hardhat.qualification.config.ts',
          'test',
          'mocha',
          '--no-compile',
          'test/SynchronizedDkgPublication.spec.ts',
        ],
        cwd: realpathSync(join(root, 'packages/interfold-contracts')),
        fixture: input,
        source: join(prepared, 'SynchronizedHonk.sol'),
      })
      assert.match(readFileSync(join(prepared, 'SynchronizedHonk.sol'), 'utf8'), /contract DkgAggregatorVerifier/)
      assert.equal(readFileSync(canonical, 'utf8'), 'untouched canonical verifier')
    }
  }
  writeFileSync(input, '{invalid')
  assert.throws(() => verifySynchronizedPublication(root, input), SyntaxError)
})
