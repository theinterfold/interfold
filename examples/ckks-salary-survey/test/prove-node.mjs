// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Node-side prover: the SAME `@interfold/ckks-salary-sdk` pipeline the
// browser runs (WASM encrypt → noir_js execute ×3 → bb.js prove ×3), used
// by the e2e harness as a fallback / for offline checks.
//
//   node test/prove-node.mjs --pubkey-hex 0x… --salary 52000 --cap 500000 --out sub.json
//   node test/prove-node.mjs --pubkey-file ../ckks-common/packages/ckks-zk-inputs/fixtures/pubkey_ps3.bin …

import { readFile, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { createRequire } from 'node:module'

const here = path.dirname(fileURLToPath(import.meta.url))
const root = path.join(here, '..')
const require = createRequire(path.join(root, 'client', 'package.json'))

const args = process.argv.slice(2)
const opt = (name, dflt) => {
  const i = args.indexOf(name)
  return i >= 0 ? args[i + 1] : dflt
}

export async function proveNode({ publicKey, salary, cap, onProgress = () => {} }) {
  // tsx-free import of the TS SDK: Node 22 needs a loader for .ts, so we
  // import the SDK through vite-node-less path: the SDK is plain TS with
  // type-only constructs, so strip types with the TypeScript transpiler.
  const ts = require('typescript')
  const src = await readFile(path.join(root, 'packages/ckks-salary-sdk/src/index.ts'), 'utf8')
  const js = ts.transpileModule(src, { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 } }).outputText
  const tmp = path.join(root, 'test/.sdk.transpiled.mjs')
  await writeFile(tmp, js)
  const sdk = await import(`${tmp}?t=${Date.now()}`)

  const wasm = await import(require.resolve('@interfold/ckks-zk-inputs'))
  const { Noir } = await import(require.resolve('@noir-lang/noir_js'))
  const { Barretenberg, BackendType, UltraHonkBackend } = await import(require.resolve('@aztec/bb.js'))
  const circuitsDir = path.join(root, 'client/public/circuits')
  const circuits = {}
  for (const [leg, name] of Object.entries(sdk.CIRCUIT_NAMES)) {
    circuits[leg] = JSON.parse(await readFile(path.join(circuitsDir, `${name}.json`), 'utf8'))
  }
  const t = performance.now()
  // Node: pin the WASM backend (the native socket backend hangs in Node).
  const api = await Barretenberg.new({ srsSize: sdk.SRS_SIZE, backend: BackendType.Wasm })
  onProgress('Barretenberg.new', `${Math.round(performance.now() - t)} ms`)
  const deps = {
    wasm,
    Noir,
    backendFor: async (circuit) => new UltraHonkBackend(circuit.bytecode, api),
    circuits,
  }
  const result = await sdk.proveSalarySubmission(deps, publicKey, salary, cap, onProgress)
  await api.destroy()
  return result
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const salary = Number(opt('--salary', '52000'))
  const cap = Number(opt('--cap', '500000'))
  let pk
  if (opt('--pubkey-hex')) {
    const h = opt('--pubkey-hex').replace(/^0x/, '')
    pk = Uint8Array.from(Buffer.from(h, 'hex'))
  } else {
    pk = new Uint8Array(await readFile(opt('--pubkey-file', path.join(root, '../ckks-common/packages/ckks-zk-inputs/fixtures/pubkey_ps3.bin'))))
  }
  const r = await proveNode({ publicKey: pk, salary, cap, onProgress: (s, d) => console.log(`  ${s}${d ? ` — ${d}` : ''}`) })
  console.log('timings (ms):', Object.fromEntries(r.timings.map((t) => [t.stage, t.millis])), 'total', r.totalMillis)
  console.log('u_commitment', r.uCommitment, 'm_commitment', r.mCommitment)
  const out = opt('--out')
  if (out) {
    await writeFile(out, JSON.stringify(r.submission, null, 2))
    console.log('wrote', out)
  }
}
