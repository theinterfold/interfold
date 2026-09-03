// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Node smoke: load the wasm, encrypt 0.42 under the ps3 test pk, solve the
// ct1_ps3 (and ct0_ps3) witness with noir_js, prove + verify with bb.js
// UltraHonk. Prints timings — these are the client-side proving numbers.
//
//   node scripts/node-smoke.mjs [--param-set 3] [--skip-ct0] [--skip-prove]
//
// Requires: `pnpm build` (dist/), `pnpm fixtures` (fixtures/pubkey_ps3.bin),
// compiled circuits in ../../../../circuits/bin/threshold/target/.

import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { performance } from 'node:perf_hooks'

const here = path.dirname(fileURLToPath(import.meta.url))
const pkg = path.join(here, '..')
const interfold = path.join(pkg, '../../../..')

const args = process.argv.slice(2)
const flag = (name) => args.includes(name)
const opt = (name, dflt) => {
  const i = args.indexOf(name)
  return i >= 0 ? args[i + 1] : dflt
}
const PARAM_SET = Number(opt('--param-set', '3'))
const suffix = PARAM_SET === 0 ? '' : `_ps${PARAM_SET}`
const VALUE = Number(opt('--value', '0.42'))
const CAP = Number(opt('--cap', '1'))

const ms = (t) => `${t.toFixed(0)} ms`
const timings = {}
async function timed(label, fn) {
  const t0 = performance.now()
  const r = await fn()
  timings[label] = performance.now() - t0
  console.log(`  ${label}: ${ms(timings[label])}`)
  return r
}

async function loadCircuit(name) {
  const file = path.join(interfold, 'circuits/bin/threshold/target', `${name}.json`)
  return JSON.parse(await readFile(file, 'utf8'))
}

async function main() {
  console.log(`ckks-zk-inputs node smoke (param set ${PARAM_SET}, value ${VALUE} / cap ${CAP})`)

  const wasm = await timed('wasm load', async () => import('../main.js'))
  console.log(`  version ${wasm.version()}`)
  const info = wasm.ckksParamSetInfo(PARAM_SET)
  console.log(`  params: N=${info.degree}, L=${info.num_limbs}, scale=2^${info.scale_bits}, bound=${info.input_bound}`)

  const pkPath = path.join(pkg, 'fixtures', `pubkey_ps${PARAM_SET}.bin`)
  const pk = new Uint8Array(await readFile(pkPath))

  const bundle = await timed('wasm encryptAndWitness', () =>
    wasm.encryptAndWitness(PARAM_SET, pk, VALUE, CAP, true, undefined),
  )
  console.log(`  ciphertext ${bundle.ciphertext_hex.length / 2} bytes, u_commitment ${bundle.u_commitment_hex}`)

  // Commitments re-derived from the input map must agree with the bundle.
  const rec = wasm.commitmentsFromInputs(PARAM_SET, bundle.ct0_inputs)
  if (rec.u_commitment_hex !== bundle.u_commitment_hex || rec.m_commitment_hex !== bundle.m_commitment_hex) {
    throw new Error('commitmentsFromInputs disagrees with the bundle')
  }
  const mp = wasm.messagePolyJson(PARAM_SET, bundle.ct0_inputs)
  if (mp.message_poly.length !== info.degree || mp.message_poly_limbs.length !== info.num_limbs) {
    throw new Error('messagePolyJson shape mismatch')
  }

  const { Noir } = await import('@noir-lang/noir_js')
  const { Barretenberg, BackendType, UltraHonkBackend } = await import('@aztec/bb.js')

  // Same as CRISP's crisp-sdk getBBApi(): in Node pin bb.js to its WASM
  // backend (the native Unix-socket backend has a 5 s socket timeout that
  // surfaces as a hung promise); `--bb-native` opts into the native one.
  // In the browser the worker backend is selected automatically.
  let api
  const getApi = async () => {
    if (api) return api
    const backend = flag('--bb-native') ? { backend: BackendType.Native } : { backend: BackendType.Wasm }
    api = await timed('bb.js Barretenberg.new (srs 2^21)', () => Barretenberg.new({ srsSize: 2 ** 21, ...backend }))
    return api
  }

  const legs = [
    { name: `user_data_encryption_ckks_ct1${suffix}`, inputs: bundle.ct1_inputs, uIdx: 2, expect: 3 },
  ]
  if (!flag('--skip-ct0')) {
    legs.push({ name: `user_data_encryption_ckks_ct0${suffix}`, inputs: bundle.ct0_inputs, uIdx: 3, expect: 4 })
  }

  for (const leg of legs) {
    console.log(`\n${leg.name}`)
    const circuit = await loadCircuit(leg.name)
    const noir = new Noir(circuit)
    const { witness, returnValue } = await timed(`noir_js execute (${leg.name})`, () => noir.execute(leg.inputs))
    const outputs = Array.isArray(returnValue) ? returnValue : Object.values(returnValue)
    if (outputs.length !== leg.expect) throw new Error(`${leg.name}: expected ${leg.expect} outputs, got ${outputs.length}`)
    const norm = (h) => `0x${BigInt(h).toString(16).padStart(64, '0')}`
    if (norm(outputs[leg.uIdx]) !== bundle.u_commitment_hex) {
      throw new Error(`${leg.name}: solved u_commitment ${outputs[leg.uIdx]} != bundle ${bundle.u_commitment_hex}`)
    }
    if (leg.uIdx === 3 && norm(outputs[2]) !== bundle.m_commitment_hex) {
      throw new Error(`${leg.name}: solved m_commitment ${outputs[2]} != bundle ${bundle.m_commitment_hex}`)
    }
    console.log(`  witness solved; u_commitment matches`)

    if (flag('--skip-prove')) continue
    const backend = new UltraHonkBackend(circuit.bytecode, await getApi())
    const proof = await timed(`bb.js generateProof (${leg.name})`, () => backend.generateProof(witness))
    console.log(`  proof ${proof.proof.length} bytes, ${proof.publicInputs.length} public inputs`)
    const ok = await timed(`bb.js verifyProof (${leg.name})`, () => backend.verifyProof(proof))
    if (!ok) throw new Error(`${leg.name}: verifyProof returned false`)
    console.log(`  verifyProof: true`)
  }
  if (api) await api.destroy()

  console.log('\nTIMINGS (ms)')
  for (const [k, v] of Object.entries(timings)) console.log(`  ${k.padEnd(52)} ${v.toFixed(0)}`)
  console.log('\nckks-zk-inputs node smoke: ok')
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
