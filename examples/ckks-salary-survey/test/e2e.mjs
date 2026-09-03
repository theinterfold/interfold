// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Headless end-to-end driver against a RUNNING stack (scripts/dev.sh):
//
//   1. create a round (admin API) → wait for the joint pk (DKG + ceremony)
//   2. N submissions produced by the REAL browser path: Playwright drives
//      the Vite client (WASM encrypt → noir_js ×3 → bb.js ×3 in Chromium),
//      the client POSTs to the server relay, the relay publishes on-chain
//   3. assert every submission emitted VerifiedInputPublished on-chain
//      (eth_getLogs against the program) and that a replayed submission is
//      rejected as a duplicate (server 409 + on-chain DuplicateSubmission)
//   4. wait for the window to close → evaluate → publish → threshold
//      decryption → results served by the API; assert mean/variance
//
//   node test/e2e.mjs [--salaries 52000,61000,63700] [--api http://127.0.0.1:8091]
//                     [--client http://127.0.0.1:5174] [--node-prover]
//
// `--node-prover` swaps step 2 for test/prove-node.mjs (same SDK, bb.js in
// Node) — used only if Chromium is unavailable; the report states which.

import { writeFileSync, mkdirSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { createRequire } from 'node:module'

const here = path.dirname(fileURLToPath(import.meta.url))
const root = path.join(here, '..')
const require = createRequire(path.join(root, 'package.json'))
// viem is a client dependency; resolve it from there (no extra root deps).
const requireClient = createRequire(path.join(root, 'client', 'package.json'))

const args = process.argv.slice(2)
const flag = (n) => args.includes(n)
const opt = (n, d) => {
  const i = args.indexOf(n)
  return i >= 0 ? args[i + 1] : d
}
const API = opt('--api', 'http://127.0.0.1:8091')
const CLIENT = opt('--client', 'http://127.0.0.1:5174')
const RPC = opt('--rpc', 'http://127.0.0.1:8545')
const SALARIES = opt('--salaries', '52000,61000,63700').split(',').map(Number)
const USE_NODE_PROVER = flag('--node-prover')
const OUT_DIR = opt('--out', '/tmp/ckks-salary-e2e')
mkdirSync(OUT_DIR, { recursive: true })

const timings = {}
const t0 = Date.now()
const log = (...a) => console.log(`[e2e +${((Date.now() - t0) / 1000).toFixed(1)}s]`, ...a)
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
const api = async (method, p, body, admin = false) => {
  const res = await fetch(`${API}${p}`, {
    method,
    headers: { 'content-type': 'application/json', ...(admin ? { 'x-admin-key': process.env.ADMIN_KEY ?? '' } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const json = await res.json().catch(() => ({}))
  return { status: res.status, json }
}
const rpc = async (method, params = []) => {
  const res = await fetch(RPC, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) })
  const j = await res.json()
  if (j.error) throw new Error(`${method}: ${JSON.stringify(j.error)}`)
  return j.result
}
const assert = (cond, msg) => {
  if (!cond) throw new Error(`ASSERTION FAILED: ${msg}`)
  log('✓', msg)
}
const expectedStats = (s) => {
  const n = s.length
  const sum = s.reduce((a, b) => a + b, 0)
  const sumsq = s.reduce((a, b) => a + b * b, 0)
  const mean = sum / n
  const variance = Math.max(0, sumsq / n - mean * mean)
  return { n, sum, sumsq, mean, variance, stddev: Math.sqrt(variance) }
}

// keccak256("VerifiedInputPublished(uint256,address,bytes32,bytes32,bytes32,bytes32,bytes32)")
const viem = await import(requireClient.resolve('viem'))
const VERIFIED_TOPIC = viem.keccak256(viem.toBytes('VerifiedInputPublished(uint256,address,bytes32,bytes32,bytes32,bytes32,bytes32)'))

async function main() {
  const health = (await api('GET', '/health')).json
  assert(health.ok, `server healthy (program ${health.program}, relayer ${health.relayer})`)
  const program = health.program.toLowerCase()
  const cap = Number(health.salary_cap)

  // 1. round
  let t = Date.now()
  const created = await api('POST', '/rounds', { duration_secs: Number(opt('--duration', '150')) }, true)
  assert(created.status === 200, `round created: e3_id=${created.json.e3_id} tx=${created.json.tx_hash}`)
  const e3Id = created.json.e3_id
  timings.request_round_ms = Date.now() - t

  t = Date.now()
  let round
  for (;;) {
    round = (await api('GET', `/rounds/${e3Id}`)).json
    if (round.public_key_hex) break
    if (Date.now() - t > 20 * 60_000) throw new Error('timed out waiting for the committee pk')
    await sleep(3000)
  }
  timings.dkg_and_ceremony_ms = Date.now() - t
  assert(round.status === 'open', `joint pk published (${(round.public_key_hex.length - 2) / 2} bytes) after ${(timings.dkg_and_ceremony_ms / 1000).toFixed(1)}s; committee ${round.committee.length} nodes; round OPEN`)

  // 2. submissions
  const submissions = []
  const perLeg = []
  let firstSubmissionJson = null
  if (!USE_NODE_PROVER) {
    const { chromium } = require('playwright')
    const chromeBin = process.env.CHROME_BIN
    const browser = await chromium.launch({ headless: true, ...(chromeBin ? { executablePath: chromeBin } : {}) })
    const page = await browser.newPage()
    page.on('console', (m) => {
      if (m.type() === 'error') log('browser console error:', m.text())
    })
    // Capture the relayed submission body so we can replay it for the dedup check.
    await page.route(`${API}/rounds/${e3Id}/submit`, async (route) => {
      const body = route.request().postDataJSON()
      if (!firstSubmissionJson) firstSubmissionJson = body.submission
      await route.continue()
    })
    await page.goto(`${CLIENT}/rounds/${e3Id}`, { waitUntil: 'networkidle' })
    const isolated = await page.evaluate(() => globalThis.crossOriginIsolated)
    log(`browser crossOriginIsolated=${isolated} (multithreaded bb.js: ${isolated})`)
    await page.getByTestId('salary-input').waitFor({ timeout: 60_000 })

    for (const [i, salary] of SALARIES.entries()) {
      t = Date.now()
      await page.getByTestId('salary-input').fill(String(salary))
      await page.getByTestId('submit-button').click()
      await page.getByTestId('submit-result').waitFor({ timeout: 10 * 60_000 })
      const total = Date.now() - t
      const tx = await page.getByTestId('tx-hash').innerText()
      const rows = await page.locator('[data-testid=timings] tbody tr').allInnerTexts()
      const legTimings = Object.fromEntries(rows.map((r) => r.split('\t')).map(([k, v]) => [k.trim(), Number(v)]))
      perLeg.push(legTimings)
      submissions.push({ salary, tx, browser_total_ms: total, timings: legTimings })
      log(`submission ${i} (salary ${salary}) accepted in browser: tx ${tx}, ${total} ms end-to-end`, legTimings)
      await page.screenshot({ path: path.join(OUT_DIR, `submission-${i}.png`), fullPage: true })
      // reset the form for the next participant
      await page.reload({ waitUntil: 'networkidle' })
      await page.getByTestId('salary-input').waitFor({ timeout: 60_000 })
    }
    await browser.close()
  } else {
    const { proveNode } = await import('./prove-node.mjs')
    const pk = Uint8Array.from(Buffer.from(round.public_key_hex.slice(2), 'hex'))
    for (const [i, salary] of SALARIES.entries()) {
      t = Date.now()
      const r = await proveNode({ publicKey: pk, salary, cap })
      if (!firstSubmissionJson) firstSubmissionJson = r.submission
      const res = await api('POST', `/rounds/${e3Id}/submit`, { submission: r.submission })
      assert(res.status === 200, `node-prover submission ${i} relayed: ${res.json.tx_hash}`)
      const legTimings = Object.fromEntries(r.timings.map((x) => [x.stage, x.millis]))
      perLeg.push(legTimings)
      submissions.push({ salary, tx: res.json.tx_hash, browser_total_ms: Date.now() - t, timings: legTimings, relay: res.json })
    }
  }
  timings.submissions = submissions

  // 3a. duplicate replay → server 409 (pre-check) AND on-chain DuplicateSubmission (eth_call)
  assert(firstSubmissionJson, 'captured a real submission body for the replay test')
  const dup = await api('POST', `/rounds/${e3Id}/submit`, { submission: firstSubmissionJson })
  assert(dup.status === 409 && dup.json.duplicate === true, `replayed submission rejected by the server as duplicate (409): ${dup.json.error}`)
  {
    const data = viem.encodeAbiParameters(
      ['bytes', 'bytes', 'bytes32[]', 'bytes', 'bytes32[]', 'bytes', 'bytes32[]'].map((type) => ({ type })),
      [
        firstSubmissionJson.ciphertextHex,
        firstSubmissionJson.ct0.proofHex,
        firstSubmissionJson.ct0.publicInputs,
        firstSubmissionJson.ct1.proofHex,
        firstSubmissionJson.ct1.publicInputs,
        firstSubmissionJson.appLeg.proofHex,
        firstSubmissionJson.appLeg.publicInputs,
      ],
    )
    const abi = viem.parseAbi(['function publishInput(uint256 e3Id, bytes data)', 'error DuplicateSubmission(uint256 e3Id, bytes32 uCommitment)'])
    const calldata = viem.encodeFunctionData({ abi, functionName: 'publishInput', args: [BigInt(e3Id), data] })
    let reverted = null
    try {
      await rpc('eth_call', [{ from: health.relayer, to: program, data: calldata, gas: '0x1ba8140' }, 'latest'])
    } catch (e) {
      reverted = String(e)
    }
    const dupSelector = viem.toFunctionSelector('DuplicateSubmission(uint256,bytes32)')
    assert(reverted && reverted.includes(dupSelector.slice(2)), `on-chain replay reverts with DuplicateSubmission (${dupSelector})`)
  }

  // 3b. VerifiedInputPublished events on-chain
  const e3Topic = '0x' + BigInt(e3Id).toString(16).padStart(64, '0')
  const logs = await rpc('eth_getLogs', [{ fromBlock: '0x0', toBlock: 'latest', address: program, topics: [VERIFIED_TOPIC, e3Topic] }])
  assert(logs.length === SALARIES.length, `${logs.length} VerifiedInputPublished events on-chain for e3 ${e3Id}`)
  for (const s of submissions) {
    assert(logs.some((l) => l.transactionHash.toLowerCase() === s.tx.toLowerCase()), `event found for tx ${s.tx}`)
  }
  round = (await api('GET', `/rounds/${e3Id}`)).json
  assert(round.submissions.length === SALARIES.length && round.submissions.every((s) => s.verified), `server indexed ${round.submissions.length} verified submissions`)
  const gas = round.submissions.map((s) => s.gas_used)
  timings.relay_gas = gas

  // 4. window close → evaluate → publish → decrypt → results
  t = Date.now()
  for (;;) {
    const now = Number(BigInt((await rpc('eth_getBlockByNumber', ['latest', false])).timestamp))
    if (now > round.input_window[1]) break
    await sleep(2000)
  }
  timings.wait_for_window_close_ms = Date.now() - t
  t = Date.now()
  const ev = await api('POST', `/rounds/${e3Id}/evaluate`, undefined, true)
  if (ev.status !== 200 && !/already evaluated/.test(ev.json.error ?? '')) throw new Error(`evaluate failed: ${JSON.stringify(ev.json)}`)
  timings.evaluate_and_publish_ms = Date.now() - t
  round = (await api('GET', `/rounds/${e3Id}`)).json
  assert(round.evaluation && round.evaluation.publish_tx_hash, `evaluated (${round.evaluation.eval_millis} ms policy) + ciphertext output published tx ${round.evaluation.publish_tx_hash}`)
  timings.policy_eval_ms = round.evaluation.eval_millis

  t = Date.now()
  for (;;) {
    round = (await api('GET', `/rounds/${e3Id}`)).json
    if (round.results) break
    if (Date.now() - t > 15 * 60_000) throw new Error('timed out waiting for the plaintext')
    await sleep(3000)
  }
  timings.threshold_decrypt_ms = Date.now() - t
  const r = round.results
  const exp = expectedStats(SALARIES)
  log('results', r)
  log('expected', exp)
  assert(round.status === 'complete', 'round COMPLETE')
  assert(r.count === SALARIES.length, `count ${r.count}`)
  const meanErr = Math.abs(r.mean - exp.mean) / exp.mean
  const varErr = exp.variance > 0 ? Math.abs(r.variance - exp.variance) / exp.variance : 0
  assert(meanErr < 1e-3, `mean ${r.mean.toFixed(2)} vs expected ${exp.mean.toFixed(2)} (rel err ${(meanErr * 100).toFixed(4)}%)`)
  assert(varErr < 2e-2, `variance ${r.variance.toFixed(2)} vs expected ${exp.variance.toFixed(2)} (rel err ${(varErr * 100).toFixed(3)}%)`)

  const report = {
    e3Id,
    program,
    prover: USE_NODE_PROVER ? 'node (bb.js wasm)' : 'browser (Playwright Chromium, multithreaded bb.js)',
    salaries: SALARIES,
    results: r,
    expected: exp,
    meanErr,
    varErr,
    timings,
    duplicate_check: { server_status: dup.status, server_error: dup.json.error },
    verified_events: logs.map((l) => ({ tx: l.transactionHash, block: Number(l.blockNumber) })),
    total_ms: Date.now() - t0,
  }
  writeFileSync(path.join(OUT_DIR, `report-${e3Id}.json`), JSON.stringify(report, null, 2))
  log(`REPORT written to ${OUT_DIR}/report-${e3Id}.json`)
  console.log('\nE2E PASS')
  console.log(JSON.stringify(report, null, 2))
}

main().catch((e) => {
  console.error('\nE2E FAIL:', e)
  process.exit(1)
})
