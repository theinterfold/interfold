// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Node-side prover smoke: the SAME `@ckks-credit/sdk` pipeline the browser runs (WASM
// coefficient-encode + encrypt → noir_js execute ×3 → bb.js prove ×3) against the ParamSet 4 fixture
// public key and a 2-leaf issuer tree (Alice = the contract fixture's vector). No chain needed.
// Prints per-leg timings; exits non-zero if any commitment link fails or the over-cap negative case
// does not fail before proving.
//
//   node scripts/prove-node.mjs [--pubkey-file ../ckks-common/packages/ckks-zk-inputs/fixtures/pubkey_ps4.bin]

import { readFile, writeFile, mkdir } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { createRequire } from 'node:module'

const here = path.dirname(fileURLToPath(import.meta.url))
const root = path.join(here, '..')
const require = createRequire(path.join(root, 'packages/ckks-credit-sdk', 'package.json'))
const args = process.argv.slice(2)
const opt = (n, d) => (args.includes(n) ? args[args.indexOf(n) + 1] : d)

const ROOT_REPO = path.join(root, '../..')
const CIRCUITS_DIR = process.env.CKKS_CIRCUITS_DIR ?? path.join(ROOT_REPO, 'circuits/bin/threshold/target')

async function loadSdk() {
  // Bundle the TS SDK for Node with esbuild (vite's), keeping the heavy deps external.
  const esbuild = require('esbuild')
  const outdir = path.join(root, 'packages/ckks-credit-sdk/.node-bundle')
  await mkdir(outdir, { recursive: true })
  const outfile = path.join(outdir, 'sdk.mjs')
  await esbuild.build({
    entryPoints: [path.join(root, 'packages/ckks-credit-sdk/src/index.ts')],
    bundle: true,
    format: 'esm',
    platform: 'node',
    target: 'node20',
    outfile,
    external: ['@aztec/bb.js', '@noir-lang/noir_js', '@interfold/ckks-zk-inputs', '@interfold/ckks-zk-inputs/init', 'viem', 'viem/*', 'poseidon-lite'],
    logLevel: 'silent',
  })
  return import(`${outfile}?t=${Date.now()}`)
}

const ALICE = { key: '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80', features: [520, 130, 350, 999, 0, 1, 777, 42] }
const BOB = { address: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8', features: [1, 2, 3, 4, 5, 6, 7, 8] }
const CAP = 1000

async function main() {
  const sdk = await loadSdk()
  const { privateKeyToAccount } = await import('viem/accounts')
  const alice = privateKeyToAccount(ALICE.key).address
  const pk = new Uint8Array(await readFile(opt('--pubkey-file', path.join(root, '../ckks-common/packages/ckks-zk-inputs/fixtures/pubkey_ps4.bin'))))

  const circuits = {}
  for (const [leg, name] of Object.entries(sdk.CIRCUIT_NAMES)) {
    circuits[leg] = JSON.parse(await readFile(path.join(CIRCUITS_DIR, `${name}.json`), 'utf8'))
  }
  sdk.setCircuits(circuits)

  const tree = new sdk.FeatureTree([
    { address: alice, features: ALICE.features },
    { address: BOB.address, features: BOB.features },
  ])
  const proof = {
    address: alice,
    features: ALICE.features,
    cap: CAP,
    merkleRoot: tree.rootHex(),
    depth: 1,
    indices: [false],
    siblings: [sdk.featureLeaf(BOB.address, BOB.features).toString()],
  }
  console.log('issuer root', proof.merkleRoot)

  // Negative: over-cap feature fails BEFORE any proof.
  let failed = null
  const t0 = performance.now()
  try {
    await sdk.encryptAndProveApplication(pk, { ...proof, features: [520, 130, 350, 1001, 0, 1, 777, 42] }, alice)
  } catch (e) {
    failed = e.message
  }
  if (!failed || !/exceeds the cap/.test(failed)) throw new Error(`over-cap did not fail as expected: ${failed}`)
  console.log(`over-cap rejected in ${Math.round(performance.now() - t0)} ms: ${failed}`)

  const sub = await sdk.encryptAndProveApplication(pk, proof, alice, undefined, (s, ms) => console.log(`  [${Math.round(ms)} ms] ${JSON.stringify(s)}`))
  console.log('timings', JSON.stringify(sub.timings))
  console.log('u_commitment', sub.uCommitment, 'm_commitment', sub.mCommitment)
  console.log('ct0 pub', sub.ct0.publicInputs)
  console.log('app pub', sub.app.publicInputs)
  if (sub.app.publicInputs[0] !== sdk.word(BigInt(CAP))) throw new Error('app cap word mismatch')
  if (sub.app.publicInputs[1] !== sdk.word(BigInt(alice))) throw new Error('app address word mismatch')
  if (sub.app.publicInputs[2] !== sdk.word(BigInt(proof.merkleRoot))) throw new Error('app root word mismatch')

  const model = { weights: [1.5, -0.75, 2.0, 1.0, -1.25, 0.5, 0.8, -0.3], bias: -1.2 }
  const z = sdk.linearScore(model, ALICE.features, CAP)
  const opened = [z + sdk.maskDot(model, sub.masks)]
  const r = sdk.recoverScore(opened, 0, model, sub.masks)
  console.log(`recovery check: opened ${opened[0].toFixed(4)} → z ${r.linear.toFixed(6)} (true ${z.toFixed(6)}) σ ${r.probability.toFixed(6)}`)
  if (Math.abs(r.linear - z) > 1e-9) throw new Error('recovery mismatch')
  const out = opt('--out')
  if (out) await writeFile(out, JSON.stringify({ submission: sub, proof }, null, 2))
  await sdk.destroyBBApi()
  console.log('PROVE-NODE OK')
}

main().catch((e) => {
  console.error('PROVE-NODE FAILED:', e)
  process.exit(1)
})
