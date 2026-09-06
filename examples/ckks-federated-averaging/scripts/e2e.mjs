// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Live end-to-end driver for the CKKS federated-averaging app (CRISP `test_e2e.sh` shape). Expects
// the stack booted by `scripts/dev.sh` (anvil + contracts + 5 ciphernodes + server :8095 + client :5178).
//
// Drives the REAL client in headless Chrome (playwright): opens a round with a 4-address client list,
// the public norm bound and min-clients = 3 (registered on-chain), waits for the committee key
// (ParamSet 5: DKG + ONE level-0 relin ceremony), then for each client selects the dev wallet in
// the navbar, types its update + private count and clicks "Encrypt update + count, prove 5 legs &
// submit" — the page coefficient-encodes + encrypts BOTH in WASM, generates the five UltraHonk
// proofs and sends the wallet transaction. Asserts:
//
//   1. an OVER-BOUND update (‖g‖² > B) fails locally before any proof;
//   2. with only 2 accepted updates the server REFUSES to evaluate (public minimum = 3);
//   3. a WRONG-BOUND submission (five valid proofs under a different bound) reverts WrongNormBound,
//      a patched `index` word reverts WrongIndex, and a REPLAY reverts AlreadySubmitted;
//   4. three updates are accepted on-chain (UpdatePublished, 5 Honk verifies each);
//   5. after evaluate → publish → threshold decrypt, the opened weighted mean equals
//      Σ nᵢ·gᵢ / Σ nᵢ of the three plaintext updates within 1e-3 per coordinate, the total count is
//      exact, and coefficient 0 is ≈ 0 (no cross terms); the client page shows the same numbers.
//
//   node scripts/e2e.mjs [--client http://127.0.0.1:5178] [--api http://127.0.0.1:8095] [--window 600]
//   CHROME_BIN=... to pin the Chrome binary (playwright 1.52 wants chromium-1169).

import { writeFileSync } from 'node:fs'
import { chromium } from 'playwright'
import { createPublicClient, createWalletClient, decodeAbiParameters, decodeErrorResult, decodeFunctionData, encodeAbiParameters, encodeFunctionData, http, parseAbi, parseAbiParameters } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'

const args = process.argv.slice(2)
const opt = (n, d) => (args.includes(n) ? args[args.indexOf(n) + 1] : d)
const CLIENT = opt('--client', 'http://127.0.0.1:5178')
const API = opt('--api', 'http://127.0.0.1:8095')
const RPC = opt('--rpc', 'http://127.0.0.1:8545')
const WINDOW_SECS = Number(opt('--window', '600'))
const REPORT = opt('--report', '/tmp/ckks-fedavg-e2e-report.json')

const D = 8
const NORM_BOUND = 2.0
const MIN_CLIENTS = 3
// Dev clients = client DEV_KEYS order (anvil #6, #7, #8, #9) with the client's DEMO_UPDATES.
const CLIENTS = [
  { key: '0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e', update: [0.25, -0.5, 0.125, 0.75, -0.0625, 0.3, -0.2, 0.1], count: 120, devIndex: 0 },
  { key: '0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356', update: [-0.1, 0.4, 0.2, -0.3, 0.5, -0.25, 0.05, 0.6], count: 40, devIndex: 1 },
  { key: '0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97', update: [0.5, 0.5, -0.5, -0.5, 0.25, 0.25, -0.25, -0.25], count: 300, devIndex: 2 },
  { key: '0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6', update: [0.0, -0.75, 0.35, 0.15, -0.45, 0.6, 0.7, -0.1], count: 15, devIndex: 3 },
].map((b) => ({ ...b, address: privateKeyToAccount(b.key).address }))
const SUBMIT = [0, 1, 2] // three real updates
const OVER_BOUND = { client: 3, update: [1, 1, 1, 1, 1, 1, 1, 1] } // ‖g‖² = 8 > 2
const WRONG_BOUND_CLIENT = 3
const WRONG_BOUND = 4.0

// Exactly what the circuit/encoder do: fixed point × 2^16 then back to f64.
const toFixed = (g) => g.map((v) => Math.round(v * 65536) / 65536)
const expectedMean = (idx) => {
  const total = idx.reduce((a, i) => a + CLIENTS[i].count, 0)
  const mean = new Array(D).fill(0)
  for (const i of idx) toFixed(CLIENTS[i].update).forEach((g, j) => (mean[j] += CLIENTS[i].count * g))
  return { mean: mean.map((m) => m / total), total }
}

const log = (m) => console.log(`[${new Date().toISOString().slice(11, 19)}] ${m}`)
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
const api = async (p, init) => {
  const r = await fetch(`${API}${p}`, init)
  if (!r.ok) throw new Error(`${p}: ${r.status} ${await r.text()}`)
  return r.json()
}
const waitFor = async (label, fn, timeoutMs, everyMs = 5000) => {
  const t0 = Date.now()
  for (;;) {
    const v = await fn().catch(() => null)
    if (v) return v
    if (Date.now() - t0 > timeoutMs) throw new Error(`timeout waiting for ${label}`)
    await sleep(everyMs)
  }
}
const revertOf = (e) => {
  // viem nests the raw revert data several `cause` levels deep — walk the chain.
  let data = null
  for (let c = e, d = 0; c && d < 8 && !data; c = c.cause, d++) {
    if (typeof c.data === 'string' && c.data.startsWith('0x')) data = c.data
  }
  data ??= (e.message.match(/custom error (0x[0-9a-f]{8}): ([0-9a-f]+)/i) ?? []).slice(1).join('')
  try {
    return decodeErrorResult({ abi: PROGRAM_ABI, data })
  } catch {
    return { errorName: 'unknown', raw: String(e.shortMessage ?? e.message).slice(0, 200) }
  }
}
const PROGRAM_ABI = parseAbi([
  'function publishInput(uint256 e3Id, bytes data)',
  'error DuplicateSubmission(uint256 e3Id, bytes32 uCommitment)',
  'error AlreadySubmitted(uint256 e3Id, address client)',
  'error WrongNormBound(uint256 got, uint256 want)',
  'error WrongSender(address proven, address sender)',
  'error WrongIndex(uint256 got, uint256 want)',
  'error NotRegistered(uint256 e3Id, address client)',
  'error RoundNotRegistered(uint256 e3Id)',
  'error WrongPublicInputCount(uint256 leg, uint256 got, uint256 want)',
  'error UCommitmentMismatch(uint256 ciphertext, bytes32 ct0Leg, bytes32 ct1Leg)',
  'error MCommitmentMismatch(uint256 ciphertext, bytes32 ct0Leg, bytes32 appLeg)',
  'error Ct0ProofInvalid(uint256 ciphertext)',
  'error Ct1ProofInvalid(uint256 ciphertext)',
  'error AppProofInvalid()',
])
// The nested five-leg envelope (`CkksFedAvgE3Program.Update`).
const ENVELOPE = parseAbiParameters(
  '((bytes, bytes, bytes32[], bytes, bytes32[]), (bytes, bytes, bytes32[], bytes, bytes32[]), bytes, bytes32[])',
)

const report = { txs: [], timings: {} }

async function main() {
  const status = await api('/status')
  log(`server ok: program ${status.programAddress}, chain ${status.chainId} block ${status.block}, ParamSet ${status.paramSet}, d ${status.d}`)
  if (status.d !== D) throw new Error(`server d = ${status.d}, e2e expects ${D}`)

  const browser = await chromium.launch({ headless: true, executablePath: process.env.CHROME_BIN || undefined })
  const context = await browser.newContext()
  const page = await context.newPage()
  page.on('console', (m) => {
    if (m.type() === 'error') console.error('  [browser]', m.text())
  })
  page.on('pageerror', (e) => console.error('  [pageerror]', e.message))

  // 1. Open a round THROUGH THE CLIENT (Rounds page → client list + bound + min → Request round).
  const tRequest = Date.now()
  await page.goto(`${CLIENT}/rounds`, { waitUntil: 'load' })
  await page.getByTestId('clients').fill(JSON.stringify(CLIENTS.map((c) => c.address)))
  await page.getByTestId('norm-bound').fill(String(NORM_BOUND))
  await page.getByTestId('min-clients').fill(String(MIN_CLIENTS))
  await page.getByTestId('duration').fill(String(WINDOW_SECS))
  await page.getByTestId('open-round').click()
  await page.waitForFunction(() => document.body.innerText.includes('requested'), null, { timeout: 120_000 })
  const rounds = await api('/rounds')
  const e3Id = rounds[0].e3Id
  log(`round #${e3Id} requested via the client (bound ${NORM_BOUND}, min ${MIN_CLIENTS}, ${CLIENTS.length} clients registered on-chain)`)

  // 2. Wait for the committee key (real DKG + the level-0 relin ceremony).
  const round = await waitFor(
    'committee key',
    async () => {
      const r = await api(`/rounds/${e3Id}`)
      return r.status === 'active' && r.publicKeyAvailable ? r : null
    },
    20 * 60_000,
  )
  report.timings.dkg_wall_secs = Math.round((Date.now() - tRequest) / 1000)
  log(`committee key published in ${report.timings.dkg_wall_secs}s (DKG + level-0 ceremony); updates open until ${new Date(round.inputWindow[1] * 1000).toISOString()}`)
  if (round.inputWindow[1] * 1000 - Date.now() < 60_000) throw new Error('update window too short — raise --window')
  if (round.normBound !== NORM_BOUND || round.minClients !== MIN_CLIENTS) throw new Error(`server params ${round.normBound}/${round.minClients} ≠ requested`)
  if (round.normBoundFixedPoint !== Math.floor(NORM_BOUND * 2 ** 32)) throw new Error(`fixed-point bound ${round.normBoundFixedPoint} ≠ ${Math.floor(NORM_BOUND * 2 ** 32)}`)
  if (JSON.stringify(round.clients.map((a) => a.toLowerCase())) !== JSON.stringify(CLIENTS.map((b) => b.address.toLowerCase()))) throw new Error('registered client order ≠ requested order')

  const submitViaClient = async (client, updateOverride, boundOverride) => {
    const b = CLIENTS[client]
    await page.goto(`${CLIENT}/rounds/${e3Id}`, { waitUntil: 'load' })
    await page.getByTestId('dev-key').selectOption(String(b.devIndex))
    await page.getByTestId('my-index').waitFor({ timeout: 20_000 })
    const shownIndex = Number(await page.getByTestId('my-index').innerText())
    if (shownIndex !== client) throw new Error(`client shows slot ${shownIndex} for client ${client}`)
    await page.getByTestId('update').fill(JSON.stringify(updateOverride ?? b.update))
    await page.getByTestId('count').fill(String(b.count))
    if (boundOverride !== undefined) await page.getByTestId('bound-override').fill(String(boundOverride))
    const t0 = Date.now()
    await page.getByTestId('submit-update').click()
    await Promise.race([
      page.getByTestId('submit-verified').waitFor({ timeout: 600_000 }),
      page.getByTestId('submit-error').waitFor({ timeout: 600_000 }),
    ])
    const error = (await page.getByTestId('submit-error').count()) ? await page.getByTestId('submit-error').innerText() : null
    const wall = Date.now() - t0
    if (error) return { error, wall, address: b.address }
    const txText = await page.locator('text=/tx 0x[0-9a-f]+/').first().innerText()
    const txHash = txText.match(/0x[0-9a-fA-F]{64}/)[0]
    const gas = await page.getByTestId('submit-gas').innerText()
    // `submit-timings` sits inside a collapsed <details>: innerText() is empty there, textContent() is not.
    const timings = JSON.parse(await page.getByTestId('submit-timings').textContent())
    return { txHash, gas: Number(gas), timings, wall, address: b.address }
  }

  // 3. Over-bound update must FAIL locally (the validity leg's norm check) before any proof.
  log(`client ${OVER_BOUND.client} submits ‖g‖² = 8 (bound ${NORM_BOUND}) — must fail before proving`)
  const over = await submitViaClient(OVER_BOUND.client, OVER_BOUND.update)
  if (!over.error || !/exceeds the round bound/.test(over.error)) throw new Error(`over-bound update did NOT fail as expected: ${JSON.stringify(over)}`)
  log(`  ✔ rejected client-side in ${over.wall} ms: "${over.error}"`)
  report.overBound = over

  // 4. Two real updates, then the server must refuse to evaluate (min clients = 3).
  const submitReal = async (c) => {
    log(`client ${c} (${CLIENTS[c].address}) submits n = ${CLIENTS[c].count} via the client…`)
    const r = await submitViaClient(c)
    if (r.error) throw new Error(`update by client ${c} failed: ${r.error}`)
    report.txs.push({ client: c, address: r.address, txHash: r.txHash, gas: r.gas, wall_ms: r.wall, timings: r.timings })
    const pm = r.timings.proveMs
    log(`  ✔ tx ${r.txHash} gas ${r.gas} — encrypt ${Math.round(r.timings.encryptMs)} ms, prove app/ct1G/ct0G/ct1C/ct0C ${Math.round(pm.app)}/${Math.round(pm.ct1G)}/${Math.round(pm.ct0G)}/${Math.round(pm.ct1C)}/${Math.round(pm.ct0C)} ms, total ${r.wall} ms`)
  }
  await submitReal(SUBMIT[0])
  await submitReal(SUBMIT[1])
  await waitFor('2 updates indexed', async () => {
    const r = await api(`/rounds/${e3Id}`)
    return r.updates.length >= 2 ? r : null
  }, 60_000, 2000)
  {
    const r = await fetch(`${API}/rounds/${e3Id}/evaluate`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' })
    const body = await r.text()
    if (r.ok || !/at least 3 clients/.test(body)) throw new Error(`server evaluated with 2 updates (min 3): ${r.status} ${body}`)
    log(`  ✔ server refused to evaluate with 2 updates: ${body}`)
    report.belowMin = body
  }

  // 4b. Wrong bound: a genuine client proves under a DIFFERENT bound (five valid proofs!) — the
  //     contract compares the validity leg's norm_bound word to the round's → WrongNormBound.
  log(`client ${WRONG_BOUND_CLIENT} submits under bound ${WRONG_BOUND} (round ${NORM_BOUND}) — the contract must reject it`)
  const wrongBound = await submitViaClient(WRONG_BOUND_CLIENT, undefined, WRONG_BOUND)
  if (!wrongBound.error || !/WrongNormBound/.test(wrongBound.error)) throw new Error(`wrong-bound submission did NOT revert with WrongNormBound: ${JSON.stringify(wrongBound)}`)
  log(`  ✔ rejected on-chain (simulation) in ${wrongBound.wall} ms: WrongNormBound`)
  report.wrongBound = { error: wrongBound.error.slice(0, 200), wall: wrongBound.wall }

  // 4c. Third real update → the minimum is met.
  await submitReal(SUBMIT[2])
  const indexed = await waitFor('3 updates indexed', async () => {
    const r = await api(`/rounds/${e3Id}`)
    return r.updates.length >= 3 && r.updates.every((x) => x.ciphertextAvailable) ? r : null
  }, 60_000, 2000)
  log(`server indexed ${indexed.updates.length} updates, all ciphertext pairs recovered from calldata`)
  for (const c of SUBMIT) {
    const u = indexed.updates.find((x) => x.publisher.toLowerCase() === CLIENTS[c].address.toLowerCase())
    if (!u || u.index !== c) throw new Error(`client ${c} indexed at slot ${u?.index}`)
  }

  // 5. Wrong index + replay, both from client #0's own wallet with its accepted calldata.
  {
    const publicClient = createPublicClient({ transport: http(RPC) })
    const first = report.txs[0]
    const tx = await publicClient.getTransaction({ hash: first.txHash })
    const account = privateKeyToAccount(CLIENTS[first.client].key)
    const wallet = createWalletClient({ account, transport: http(RPC) })

    // 5a. Patch the app leg's index public input → WrongIndex (checked before proof verification).
    const { args: [txE3Id, data] } = decodeFunctionData({ abi: PROGRAM_ABI, data: tx.input })
    const [env] = decodeAbiParameters(ENVELOPE, data)
    const appPub = [...env[3]]
    appPub[2] = `0x${'00'.repeat(31)}05`
    const badData = encodeFunctionData({ abi: PROGRAM_ABI, functionName: 'publishInput', args: [txE3Id, encodeAbiParameters(ENVELOPE, [[env[0], env[1], env[2], appPub]])] })
    let wrongIndex = null
    try {
      await publicClient.call({ account, to: tx.to, data: badData, gas: 29_000_000n })
    } catch (e) {
      wrongIndex = revertOf(e)
    }
    if (!wrongIndex) throw new Error('wrong-index envelope did NOT revert')
    // The contract rejects the sender's second submission first (AlreadySubmitted) or the index — both prove the binding.
    if (!['WrongIndex', 'AlreadySubmitted'].includes(wrongIndex.errorName)) throw new Error(`wrong-index reverted with ${wrongIndex.errorName}`)
    report.wrongIndex = { errorName: wrongIndex.errorName, args: wrongIndex.args?.map(String) }
    log(`  ✔ patched-index envelope reverted: ${wrongIndex.errorName}(${(wrongIndex.args ?? []).map(String).join(', ')})`)

    // 5b. Replay the exact accepted calldata → AlreadySubmitted (simulate, then mine for on-chain evidence).
    let reverted = null
    try {
      await publicClient.call({ account, to: tx.to, data: tx.input, gas: 29_000_000n })
    } catch (e) {
      reverted = revertOf(e)
    }
    if (!reverted) throw new Error('replay of an accepted update did NOT revert')
    let replayTx = null
    try {
      replayTx = await wallet.sendTransaction({ to: tx.to, data: tx.input, gas: 29_000_000n, chain: null })
      const rc = await publicClient.waitForTransactionReceipt({ hash: replayTx })
      if (rc.status === 'success') throw new Error('replay transaction SUCCEEDED')
    } catch (e) {
      if (String(e.message).includes('SUCCEEDED')) throw e
    }
    report.replay = { errorName: reverted.errorName, args: reverted.args?.map(String), tx: replayTx }
    log(`  ✔ replay reverted: ${reverted.errorName}${reverted.args ? `(${reverted.args.map(String).join(', ')})` : ''}${replayTx ? ` (mined revert ${replayTx})` : ''}`)
    if (reverted.errorName !== 'AlreadySubmitted') throw new Error(`replay reverted with ${reverted.errorName}, expected AlreadySubmitted`)
  }

  // 6. Close the window (anvil: jump chain time past inputWindow[1]) → deadline hook evaluates +
  //    publishes ("Evaluate now" is the manual fallback) → threshold decryption → results.
  {
    const publicClient = createPublicClient({ transport: http(RPC) })
    // The ciphernodes' EVM gateway FAILS CLOSED when block time runs > 300 s ahead of their wall
    // clock — burn the excess window in real time first, then jump at most MAX_JUMP.
    const MAX_JUMP = 250
    let latest = await publicClient.getBlock()
    const remaining = Number(round.inputWindow[1]) - Number(latest.timestamp)
    if (remaining > MAX_JUMP) {
      log(`window has ${remaining}s left; waiting ${remaining - MAX_JUMP}s in real time (node drift guard is 300 s)`)
      await sleep((remaining - MAX_JUMP) * 1000)
      latest = await publicClient.getBlock()
    }
    const jump = Number(round.inputWindow[1]) - Number(latest.timestamp) + 5
    if (jump > 0) {
      await fetch(RPC, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'evm_increaseTime', params: [jump] }) })
      await fetch(RPC, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'evm_mine', params: [] }) })
      log(`update window closed (chain time +${jump}s)`)
    }
  }
  const tEval = Date.now()
  const hooked = await waitFor('deadline hook', async () => {
    const r = await api(`/rounds/${e3Id}`)
    return r.status !== 'active' ? r : null
  }, 90_000, 3000).catch(() => null)
  if (!hooked) {
    log('deadline hook did not fire within 90 s — clicking "Evaluate now"')
    await page.goto(`${CLIENT}/rounds/${e3Id}`, { waitUntil: 'load' })
    await page.getByTestId('evaluate').click()
  }
  const published = await waitFor('ciphertext published', async () => {
    const r = await api(`/rounds/${e3Id}`)
    if (r.status === 'evaluating' && r.error) log(`  (evaluating: ${r.error})`)
    return r.status === 'published' || r.status === 'finished' ? r : null
  }, 15 * 60_000)
  log(`evaluated + published (${published.timings.evaluate_ms} ms eval) — waiting for the threshold decryption`)
  const finished = await waitFor('plaintext', async () => {
    const r = await api(`/rounds/${e3Id}`)
    return r.status === 'finished' ? r : null
  }, 15 * 60_000)
  report.timings.evaluate_to_plaintext_secs = Math.round((Date.now() - tEval) / 1000)
  report.serverTimings = finished.timings

  // 7. Assertions on the opened output.
  const { opened, mean, totalCount } = finished.results
  log(`opened[0..${D + 2}]: ${JSON.stringify(opened.slice(0, D + 2))} · mean ${JSON.stringify(mean)} · total ${totalCount}`)
  const want = expectedMean(SUBMIT)
  if (Math.abs(totalCount - want.total) > 0.01) throw new Error(`total count ${totalCount} ≠ ${want.total}`)
  if (Math.abs(opened[0]) > 1e-2) throw new Error(`coefficient 0 = ${opened[0]}, expected ≈ 0`)
  for (let j = 0; j < D; j++) {
    if (Math.abs(mean[j] - want.mean[j]) > 1e-3) throw new Error(`mean[${j}] = ${mean[j]} ≠ ${want.mean[j]}`)
  }
  for (let k = D + 2; k < opened.length; k++) {
    if (Math.abs(opened[k]) > 1e-2) throw new Error(`coefficient ${k} = ${opened[k]}, expected ≈ 0`)
  }
  log(`  ✔ network-computed weighted mean matches Σ nᵢ·gᵢ / Σ nᵢ (total ${want.total}) within 1e-3; no stray coefficients`)

  // The page shows the same numbers.
  await page.goto(`${CLIENT}/rounds/${e3Id}`, { waitUntil: 'load' })
  await page.getByTestId('total-count').waitFor({ timeout: 30_000 })
  const shownTotal = Number((await page.getByTestId('total-count').innerText()).replace(/[^0-9.-]/g, ''))
  if (shownTotal !== want.total) throw new Error(`page shows total ${shownTotal}, expected ${want.total}`)
  for (let j = 0; j < D; j++) {
    const shown = Number(await page.getByTestId(`mean-${j}`).innerText())
    if (Math.abs(shown - want.mean[j]) > 1e-3) throw new Error(`page shows mean[${j}] = ${shown}, expected ${want.mean[j]}`)
  }
  await page.screenshot({ path: '/tmp/ckks-fedavg-results.png', fullPage: true })

  report.e3Id = e3Id
  report.opened = opened
  report.mean = mean
  report.totalCount = totalCount
  report.expected = want
  writeFileSync(REPORT, JSON.stringify(report, null, 2))
  log(`REPORT written to ${REPORT}`)
  await browser.close()
  console.log('\nCKKS FEDERATED AVERAGING E2E PASSED')
}

main().catch((e) => {
  console.error('\nE2E FAILED:', e)
  writeFileSync(REPORT, JSON.stringify({ ...report, failed: String(e.message ?? e) }, null, 2))
  process.exit(1)
})
