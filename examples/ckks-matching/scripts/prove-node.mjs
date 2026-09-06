// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Node-side prover smoke: the SAME `@ckks-matching/sdk` pipeline the browser runs (WASM
// coefficient-encode + encrypt ×2 → noir_js execute ×5 → bb.js prove ×5) against the ParamSet 5
// fixture public key, for BOTH parties (A = forward, B = reversed). No chain needed. Prints per-leg
// timings; exits non-zero if any commitment link fails or the out-of-range negative case does not
// fail before proving.
//
//   node scripts/prove-node.mjs [--pubkey-file ../ckks-common/packages/ckks-zk-inputs/fixtures/pubkey_ps5.bin] [--out out.json]

import { readFile, writeFile, mkdir } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { createRequire } from 'node:module'

const here = path.dirname(fileURLToPath(import.meta.url))
const root = path.join(here, '..')
const require = createRequire(path.join(root, 'packages/ckks-matching-sdk', 'package.json'))
const args = process.argv.slice(2)
const opt = (n, d) => (args.includes(n) ? args[args.indexOf(n) + 1] : d)

const ROOT_REPO = path.join(root, '../..')
const CIRCUITS_DIR = process.env.CKKS_CIRCUITS_DIR ?? path.join(ROOT_REPO, 'circuits/bin/threshold/target')

async function loadSdk() {
  // Bundle the TS SDK for Node with esbuild (vite's), keeping the heavy deps external.
  const esbuild = require('esbuild')
  const outdir = path.join(root, 'packages/ckks-matching-sdk/.node-bundle')
  await mkdir(outdir, { recursive: true })
  const outfile = path.join(outdir, 'sdk.mjs')
  await esbuild.build({
    entryPoints: [path.join(root, 'packages/ckks-matching-sdk/src/index.ts')],
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

// The contract fixture's parties and vectors (`gen_ckks_matching_prover`): A = anvil #0, B = anvil #1.
const A = { key: '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80', raw: [50, -25, 100, -100, 12.5, 0, 75, -50, 30, -70, 90, -10, 60, 20, -40, 5] }
const B = { key: '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d', raw: [40, 30, -20, 90, -100, 100, 10, 50, -60, 80, 25, 75, -35, 15, 95, -5] }
const CAP = 100

async function main() {
  const sdk = await loadSdk()
  const { privateKeyToAccount } = await import('viem/accounts')
  const a = privateKeyToAccount(A.key).address
  const b = privateKeyToAccount(B.key).address
  const pk = new Uint8Array(await readFile(opt('--pubkey-file', path.join(root, '../ckks-common/packages/ckks-zk-inputs/fixtures/pubkey_ps5.bin'))))

  const circuits = {}
  for (const [leg, name] of Object.entries(sdk.CIRCUIT_NAMES)) {
    circuits[leg] = JSON.parse(await readFile(path.join(CIRCUITS_DIR, `${name}.json`), 'utf8'))
  }
  sdk.setCircuits(circuits)

  const va = sdk.normalise(A.raw, CAP)
  const vb = sdk.normalise(B.raw, CAP)

  // Negative: an entry outside [-1, 1] fails BEFORE any proof.
  let failed = null
  const t0 = performance.now()
  try {
    await sdk.encryptAndProveSubmission(pk, sdk.normalise([...A.raw.slice(0, 15), 150], CAP), 'a', 0, a, a)
  } catch (e) {
    failed = e.message
  }
  if (!failed || !/outside \[-1, 1\]/.test(failed)) throw new Error(`out-of-range did not fail as expected: ${failed}`)
  console.log(`out-of-range rejected in ${Math.round(performance.now() - t0)} ms: ${failed}`)
  // Negative: role/slot mismatch fails before any proof.
  failed = null
  try {
    await sdk.encryptAndProveSubmission(pk, va, 'b', 0, a, a)
  } catch (e) {
    failed = e.message
  }
  if (!failed || !/does not match role/.test(failed)) throw new Error(`role mismatch did not fail as expected: ${failed}`)
  console.log(`role/slot mismatch rejected: ${failed}`)

  const results = {}
  for (const [role, index, sender, values] of [
    ['a', 0, a, va],
    ['b', 1, b, vb],
  ]) {
    console.log(`--- party ${role.toUpperCase()} (slot ${index}, ${sdk.roleLayout(role)}) ${sender}`)
    const sub = await sdk.encryptAndProveSubmission(pk, values, role, index, sender, sender, undefined, (s, ms) => console.log(`  [${Math.round(ms)} ms] ${JSON.stringify(s)}`))
    console.log('timings', JSON.stringify(sub.timings))
    console.log('u_commitment vec', sub.uCommitmentVec, 'mask', sub.uCommitmentMask)
    console.log('m_commitment vec', sub.mCommitmentVec, 'mask', sub.mCommitmentMask)
    console.log('app pub', sub.app.publicInputs)
    if (sub.app.publicInputs[0] !== sdk.word(BigInt(sdk.roleBit(role)))) throw new Error('app role word mismatch')
    if (sub.app.publicInputs[1] !== sdk.word(BigInt(sender))) throw new Error('app address word mismatch')
    if (sub.app.publicInputs[2] !== sdk.word(BigInt(index))) throw new Error('app index word mismatch')
    const envelope = sdk.encodeSubmissionEnvelope(sub)
    console.log(`envelope ${(envelope.length - 2) / 2} bytes`)
    results[role] = sub
  }

  const expected = sdk.expectedScore(va, vb)
  console.log(`expected score ⟨a, b⟩ = ${expected.toFixed(6)} (the opened coefficient 0 will be ${(-expected).toFixed(6)})`)
  const out = opt('--out')
  if (out) await writeFile(out, JSON.stringify({ a: results.a, b: results.b, expectedScore: expected }, null, 2))
  await sdk.destroyBBApi()
  console.log('PROVE-NODE OK')
}

main().catch((e) => {
  console.error('PROVE-NODE FAILED:', e)
  process.exit(1)
})
