// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Node-side prover smoke: the SAME `@ckks-fedavg/sdk` pipeline the browser runs (WASM
// coefficient-encode + encrypt ×2 → noir_js execute ×5 → bb.js prove ×5) against the ParamSet 5
// fixture public key. No chain needed. Prints per-leg timings; exits non-zero if any commitment
// link fails or the over-bound / bad-count negative cases do not fail before proving.
//
//   node scripts/prove-node.mjs [--pubkey-file ../ckks-common/packages/ckks-zk-inputs/fixtures/pubkey_ps5.bin] [--out /tmp/x.json]

import { readFile, writeFile, mkdir } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { createRequire } from 'node:module'

const here = path.dirname(fileURLToPath(import.meta.url))
const root = path.join(here, '..')
const require = createRequire(path.join(root, 'packages/ckks-fedavg-sdk', 'package.json'))
const args = process.argv.slice(2)
const opt = (n, d) => (args.includes(n) ? args[args.indexOf(n) + 1] : d)

const ROOT_REPO = path.join(root, '../..')
const CIRCUITS_DIR = process.env.CKKS_CIRCUITS_DIR ?? path.join(ROOT_REPO, 'circuits/bin/threshold/target')

async function loadSdk() {
  // Bundle the TS SDK for Node with esbuild (vite's), keeping the heavy deps external.
  const esbuild = require('esbuild')
  const outdir = path.join(root, 'packages/ckks-fedavg-sdk/.node-bundle')
  await mkdir(outdir, { recursive: true })
  const outfile = path.join(outdir, 'sdk.mjs')
  await esbuild.build({
    entryPoints: [path.join(root, 'packages/ckks-fedavg-sdk/src/index.ts')],
    bundle: true,
    format: 'esm',
    platform: 'node',
    target: 'node20',
    outfile,
    external: ['@aztec/bb.js', '@noir-lang/noir_js', '@interfold/ckks-zk-inputs', '@interfold/ckks-zk-inputs/init', 'viem', 'viem/*'],
    logLevel: 'silent',
  })
  return import(`${outfile}?t=${Date.now()}`)
}

const ALICE_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
const UPDATE = [0.25, -0.5, 0.125, 0.75, -0.0625, 0.3, -0.2, 0.1]
const COUNT = 120
const NORM_BOUND = 2.0

async function main() {
  const sdk = await loadSdk()
  const { privateKeyToAccount } = await import('viem/accounts')
  const alice = privateKeyToAccount(ALICE_KEY).address
  const pk = new Uint8Array(await readFile(opt('--pubkey-file', path.join(root, '../ckks-common/packages/ckks-zk-inputs/fixtures/pubkey_ps5.bin'))))

  const circuits = {}
  for (const [leg, name] of Object.entries(sdk.CIRCUIT_NAMES)) {
    circuits[leg] = JSON.parse(await readFile(path.join(CIRCUITS_DIR, `${name}.json`), 'utf8'))
  }
  sdk.setCircuits(circuits)

  const slot = { address: alice, index: 0, d: sdk.D, normBound: NORM_BOUND, normBoundFixedPoint: sdk.normBoundFixedPoint(NORM_BOUND) }

  // Negatives: fail BEFORE any proof.
  const expectFail = async (label, re, fn) => {
    let failed = null
    const t0 = performance.now()
    try {
      await fn()
    } catch (e) {
      failed = e.message
    }
    if (!failed || !re.test(failed)) throw new Error(`${label} did not fail as expected: ${failed}`)
    console.log(`${label} rejected in ${Math.round(performance.now() - t0)} ms: ${failed}`)
  }
  await expectFail('over-bound', /exceeds the round bound/, () => sdk.encryptAndProveUpdate(pk, { ...slot, normBound: 0.5, normBoundFixedPoint: sdk.normBoundFixedPoint(0.5) }, UPDATE, COUNT, alice))
  await expectFail('entry-out-of-range', /outside/, () => sdk.encryptAndProveUpdate(pk, slot, [1.5, ...UPDATE.slice(1)], COUNT, alice))
  await expectFail('bad-count', /sample count/, () => sdk.encryptAndProveUpdate(pk, slot, UPDATE, 1024, alice))

  const sub = await sdk.encryptAndProveUpdate(pk, slot, UPDATE, COUNT, alice, (s, ms) => console.log(`  [${Math.round(ms)} ms] ${JSON.stringify(s)}`))
  console.log('timings', JSON.stringify(sub.timings))
  console.log('u_commitment G', sub.uCommitmentG, 'C', sub.uCommitmentC)
  console.log('m_commitment G', sub.mCommitmentG, 'C', sub.mCommitmentC)
  console.log('app pub', sub.app.publicInputs)
  if (sub.app.publicInputs[0] !== sdk.word(BigInt(slot.normBoundFixedPoint))) throw new Error('app norm_bound word mismatch')
  if (sub.app.publicInputs[1] !== sdk.word(BigInt(alice))) throw new Error('app address word mismatch')
  if (sub.app.publicInputs[2] !== sdk.word(0n)) throw new Error('app index word mismatch')

  // Weighted-mean oracle on a fake opened vector (this client alone): mean == update, total == count.
  const opened = sdk.gradientBlockLayout(UPDATE, 64).map((v) => v * COUNT)
  const r = sdk.weightedMean(opened, sdk.D)
  if (Math.round(r.totalCount) !== COUNT || r.mean.some((m, j) => Math.abs(m - UPDATE[j]) > 1e-9)) throw new Error('weighted-mean mismatch')
  console.log('weighted-mean check ok:', r)
  const out = opt('--out')
  if (out) await writeFile(out, JSON.stringify({ submission: sub, slot }, null, 2))
  await sdk.destroyBBApi()
  console.log('PROVE-NODE OK')
}

main().catch((e) => {
  console.error('PROVE-NODE FAILED:', e)
  process.exit(1)
})
