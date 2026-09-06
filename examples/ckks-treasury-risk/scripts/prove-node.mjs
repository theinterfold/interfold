// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Node-side prover smoke: the SAME `@ckks-treasury/sdk` pipeline the browser runs (WASM
// coefficient-encode + encrypt ×3 → noir_js execute ×7 → bb.js prove ×7) against the ParamSet 5
// fixture public key, for TWO DAOs under the contract fixture's weights. No chain needed. Prints
// per-leg timings; exits non-zero if any commitment link fails or the out-of-range / wrong-slot
// cases do not fail before proving.
//
//   node scripts/prove-node.mjs [--pubkey-file ../ckks-common/packages/ckks-zk-inputs/fixtures/pubkey_ps5.bin] [--out out.json]

import { readFile, writeFile, mkdir } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { createRequire } from 'node:module'

const here = path.dirname(fileURLToPath(import.meta.url))
const root = path.join(here, '..')
const require = createRequire(path.join(root, 'packages/ckks-treasury-sdk', 'package.json'))
const args = process.argv.slice(2)
const opt = (n, d) => (args.includes(n) ? args[args.indexOf(n) + 1] : d)

const ROOT_REPO = path.join(root, '../..')
const CIRCUITS_DIR = process.env.CKKS_CIRCUITS_DIR ?? path.join(ROOT_REPO, 'circuits/bin/threshold/target')

async function loadSdk() {
  // Bundle the TS SDK for Node with esbuild (vite's), keeping the heavy deps external.
  const esbuild = require('esbuild')
  const outdir = path.join(root, 'packages/ckks-treasury-sdk/.node-bundle')
  await mkdir(outdir, { recursive: true })
  const outfile = path.join(outdir, 'sdk.mjs')
  await esbuild.build({
    entryPoints: [path.join(root, 'packages/ckks-treasury-sdk/src/index.ts')],
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

// The contract fixture's weights (`gen_ckks_treasury_prover`): [0.5, -0.25, 1.0, 0.125].
const WEIGHTS = [0.5, -0.25, 1.0, 0.125]
// DAO 0 = anvil #0 with the fixture's book; DAO 1 = anvil #1 with a second book.
const DAOS = [
  { key: '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80', raw: [30, 10, 45, 15] },
  { key: '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d', raw: [20, 10, 0, 10] },
]
const CAP = 100

async function main() {
  const sdk = await loadSdk()
  const { privateKeyToAccount } = await import('viem/accounts')
  const addrs = DAOS.map((d) => privateKeyToAccount(d.key).address)
  const pk = new Uint8Array(await readFile(opt('--pubkey-file', path.join(root, '../ckks-common/packages/ckks-zk-inputs/fixtures/pubkey_ps5.bin'))))

  const circuits = {}
  for (const [leg, name] of Object.entries(sdk.CIRCUIT_NAMES)) {
    circuits[leg] = JSON.parse(await readFile(path.join(CIRCUITS_DIR, `${name}.json`), 'utf8'))
  }
  sdk.setCircuits(circuits)

  const books = DAOS.map((d) => sdk.normalise(d.raw, CAP))

  // Negative: an exposure outside [0, 1] fails BEFORE any proof.
  let failed = null
  const t0 = performance.now()
  try {
    await sdk.encryptAndProveSubmission(pk, sdk.normalise([30, 10, 150, 15], CAP), WEIGHTS, 0, addrs[0], addrs[0])
  } catch (e) {
    failed = e.message
  }
  if (!failed || !/outside \[0, 1\]/.test(failed)) throw new Error(`out-of-range did not fail as expected: ${failed}`)
  console.log(`out-of-range rejected in ${Math.round(performance.now() - t0)} ms: ${failed}`)
  // Negative: a weight outside [-1, 1] fails before any proof.
  failed = null
  try {
    await sdk.encryptAndProveSubmission(pk, books[0], [1.5, 0, 0, 0], 0, addrs[0], addrs[0])
  } catch (e) {
    failed = e.message
  }
  if (!failed || !/outside \[-1, 1\]/.test(failed)) throw new Error(`out-of-range weight did not fail as expected: ${failed}`)
  console.log(`out-of-range weight rejected: ${failed}`)
  // Negative: slot registered to a different address fails before any proof.
  failed = null
  try {
    await sdk.encryptAndProveSubmission(pk, books[0], WEIGHTS, 0, addrs[1], addrs[0])
  } catch (e) {
    failed = e.message
  }
  if (!failed || !/different address/.test(failed)) throw new Error(`slot/address mismatch did not fail as expected: ${failed}`)
  console.log(`slot/address mismatch rejected: ${failed}`)

  const results = []
  const fixedW = sdk.toFixedPoint(WEIGHTS)
  for (const [index, sender] of addrs.entries()) {
    console.log(`--- DAO slot ${index} ${sender}`)
    const sub = await sdk.encryptAndProveSubmission(pk, books[index], WEIGHTS, index, sender, sender, undefined, (s, ms) => console.log(`  [${Math.round(ms)} ms] ${JSON.stringify(s)}`))
    console.log('timings', JSON.stringify(sub.timings))
    console.log('u_commitment fwd', sub.uCommitmentFwd, 'rev', sub.uCommitmentRev, 'mask', sub.uCommitmentMask)
    console.log('m_commitment fwd', sub.mCommitmentFwd, 'rev', sub.mCommitmentRev, 'mask', sub.mCommitmentMask)
    console.log('app pub', sub.app.publicInputs)
    if (sub.app.publicInputs.length !== sdk.APP_PUBLIC_INPUTS) throw new Error('app public input count mismatch')
    for (let a = 0; a < sdk.ASSETS; a++) {
      if (sub.app.publicInputs[sdk.WORD_WEIGHTS + a] !== sdk.signedFieldWord(fixedW[a])) throw new Error(`app weight word ${a} mismatch`)
    }
    if (sub.app.publicInputs[sdk.WORD_ADDRESS] !== sdk.word(BigInt(sender))) throw new Error('app address word mismatch')
    if (sub.app.publicInputs[sdk.WORD_INDEX] !== sdk.word(BigInt(index))) throw new Error('app index word mismatch')
    const legs = ['ct0F', 'ct1F', 'ct0R', 'ct1R', 'ct0M', 'ct1M', 'app']
    for (const leg of legs) if (!sub[leg]?.proof || sub[leg].proof.length < 100) throw new Error(`leg ${leg} has no proof`)
    const envelope = sdk.encodeSubmissionEnvelope(sub)
    console.log(`envelope ${(envelope.length - 2) / 2} bytes (${legs.length} legs proven)`)
    results.push(sub)
  }
  // The fixture weight words: w_1 = -0.25 → p − 16384.
  const wordsOnChain = sdk.weightWords(WEIGHTS)
  if (wordsOnChain[1] !== sdk.word(21888242871839275222246405745257275088548364400416034343698204186575808495617n - 16384n)) throw new Error('weight word encoding mismatch')

  const expected = sdk.expectedRisk(books, WEIGHTS)
  console.log(`expected risk Σ_a w_a (Σ_i x_{i,a})² = ${expected.toFixed(6)} (the opened coefficient 0 will be ${(-expected).toFixed(6)})`)
  const out = opt('--out')
  if (out) await writeFile(out, JSON.stringify({ daos: results, expectedRisk: expected }, null, 2))
  await sdk.destroyBBApi()
  console.log(`PROVE-NODE OK (${results.length} DAOs × 7 legs)`)
}

main().catch((e) => {
  console.error('PROVE-NODE FAILED:', e)
  process.exit(1)
})
