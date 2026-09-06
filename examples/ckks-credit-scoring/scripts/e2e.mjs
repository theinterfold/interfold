// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Live end-to-end driver for the CKKS credit-scoring app (CRISP `test_e2e.sh` shape). Expects the
// stack booted by `scripts/dev.sh` (anvil + contracts + 5 ciphernodes + server :8092 + client :5175).
//
// Drives the REAL client in headless Chrome (playwright): opens a round with a 5-address issuer
// snapshot + the public model (registered on-chain in fixed point with the applicant list), waits
// for the committee key (ParamSet 4: DKG + TWO per-level relin ceremonies at levels 1 and 2), then
// for each applicant selects the dev wallet in the navbar and clicks "Encrypt logit + mask, prove 5
// legs & apply" — the page computes the model's logit over the attested features, samples an output
// mask, slot-encodes + encrypts BOTH in WASM, generates the five UltraHonk proofs and sends the
// wallet transaction. Asserts:
//
//   1. an OUT-OF-RANGE feature (x_3 = cap + 1, not the attested one) fails at proving;
//   2. three attested applications are accepted on-chain (ApplicationPublished, 5 Honk verifies);
//   3. a WRONG-MODEL application (proven under a different model through the client) reverts with
//      WrongModel, and a WRONG-ROOT envelope (app public input [2] patched) reverts with WrongRoot;
//   4. a REPLAY of an accepted envelope reverts (AlreadyApplied: one application per sender);
//   5. after evaluate → publish → threshold decrypt, every applicant's browser recovers
//      σ_cubic(⟨w,x⟩/cap + b) — computed by the NETWORK on the encrypted logit — within 1e-2 from
//      its own mask, and every OPENED raw value is > 0.5 away from every true score (the masks
//      hide the probabilities from everyone else).
//
//   node scripts/e2e.mjs [--client http://127.0.0.1:5175] [--api http://127.0.0.1:8092] [--window 600]
//   CHROME_BIN=... to pin the Chrome binary (playwright 1.52 wants chromium-1169).

import { writeFileSync } from 'node:fs'
import { chromium } from 'playwright'
import { createPublicClient, createWalletClient, decodeAbiParameters, decodeErrorResult, decodeFunctionData, encodeAbiParameters, encodeFunctionData, http, parseAbi, parseAbiParameters } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'

const args = process.argv.slice(2)
const opt = (n, d) => (args.includes(n) ? args[args.indexOf(n) + 1] : d)
const CLIENT = opt('--client', 'http://127.0.0.1:5175')
const API = opt('--api', 'http://127.0.0.1:8092')
const RPC = opt('--rpc', 'http://127.0.0.1:8545')
const WINDOW_SECS = Number(opt('--window', '600'))
const REPORT = opt('--report', '/tmp/ckks-credit-e2e-report.json')

const CAP = 1000
// Dev applicants = client DEV_KEYS order (anvil #6, #7, #8, #9, #0) with the default snapshot features
// (must equal the server's `get_mock_applicants` and the client's DEFAULT_FEATURES).
const APPLICANTS = [
  { key: '0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e', features: [520, 130, 350, 999, 0, 1, 777, 42], devIndex: 0 },
  { key: '0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356', features: [900, 850, 700, 120, 300, 640, 210, 980], devIndex: 1 },
  { key: '0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97', features: [100, 200, 300, 400, 500, 600, 700, 800], devIndex: 2 },
  { key: '0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6', features: [1000, 1000, 1000, 1000, 0, 0, 0, 0], devIndex: 3 },
  { key: '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80', features: [250, 750, 125, 875, 333, 666, 999, 1], devIndex: 4 },
].map((b) => ({ ...b, address: privateKeyToAccount(b.key).address }))
const MODEL = { weights: [1.5, -0.75, 2.0, 1.0, -1.25, 0.5, 0.8, -0.3], bias: -1.2 }
const WRONG_MODEL = { weights: [1.5, -0.75, 2.0, 1.0, -1.25, 0.5, 0.8, -0.3], bias: -1.1 }
const APPLY = [0, 2, 4] // three real applications
const OUT_OF_RANGE = { applicant: 1, features: [900, 850, 700, 1001, 300, 640, 210, 980] } // x_3 = cap + 1
const WRONG_MODEL_APPLICANT = 3

// The logit EXACTLY as the circuit pins it (fixed point × 2^16) and the cubic sigmoid the network
// evaluates (`e3_trckks::policy::sigmoid_cubic`).
const fixedPoint = (m) => ({ weights: m.weights.map((w) => Math.round(w * 65536)), bias: Math.round(m.bias * 65536) })
const linear = (features) => {
  const fp = fixedPoint(MODEL)
  let acc = 0n
  for (let j = 0; j < 8; j++) acc += BigInt(fp.weights[j]) * BigInt(features[j])
  acc += BigInt(fp.bias) * BigInt(CAP)
  return Number(acc) / (65536 * CAP)
}
const sigmoidCubic = (z) => 0.5 + 0.197 * z - 0.004 * z * z * z

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
  'error AlreadyApplied(uint256 e3Id, address applicant)',
  'error WrongRoot(bytes32 got, bytes32 want)',
  'error WrongSender(address proven, address sender)',
  'error WrongCap(uint256 got, uint256 want)',
  'error WrongIndex(uint256 got, uint256 want)',
  'error WrongModel(uint256 word, bytes32 got, bytes32 want)',
  'error NotRegistered(uint256 e3Id, address applicant)',
  'error RoundNotRegistered(uint256 e3Id)',
  'error UCommitmentMismatch(uint256 ciphertext, bytes32 ct0Leg, bytes32 ct1Leg)',
  'error MCommitmentMismatch(uint256 ciphertext, bytes32 ct0Leg, bytes32 appLeg)',
  'error Ct0ProofInvalid(uint256 ciphertext)',
  'error Ct1ProofInvalid(uint256 ciphertext)',
  'error AppProofInvalid()',
])
const ENVELOPE = parseAbiParameters(
  'bytes ctZ, bytes ct0ProofZ, bytes32[] ct0PubZ, bytes ct1ProofZ, bytes32[] ct1PubZ, bytes ctM, bytes ct0ProofM, bytes32[] ct0PubM, bytes ct1ProofM, bytes32[] ct1PubM, bytes appProof, bytes32[] appPub',
)

const report = { txs: [], timings: {}, recovered: [] }

async function main() {
  const snapshot = APPLICANTS.map((b) => ({ address: b.address, features: b.features }))
  const status = await api('/status')
  log(`server ok: program ${status.programAddress}, chain ${status.chainId} block ${status.block}, ParamSet ${status.paramSet}`)

  const browser = await chromium.launch({ headless: true, executablePath: process.env.CHROME_BIN || undefined })
  const context = await browser.newContext()
  const page = await context.newPage()
  page.on('console', (m) => {
    if (m.type() === 'error') console.error('  [browser]', m.text())
  })
  page.on('pageerror', (e) => console.error('  [pageerror]', e.message))

  // 1. Open a round THROUGH THE CLIENT (Rounds page → snapshot + model → Request round).
  const tRequest = Date.now()
  await page.goto(`${CLIENT}/rounds`, { waitUntil: 'load' })
  await page.getByTestId('snapshot').fill(JSON.stringify(snapshot))
  await page.getByTestId('model').fill(JSON.stringify(MODEL))
  await page.getByTestId('duration').fill(String(WINDOW_SECS))
  await page.getByTestId('open-round').click()
  await page.waitForFunction(() => document.body.innerText.includes('requested'), null, { timeout: 120_000 })
  const rounds = await api('/rounds')
  const e3Id = rounds[0].e3Id
  log(`round #${e3Id} requested via the client (root + fixed-point model + applicant list registered on-chain)`)

  // 2. Wait for the committee key (real DKG + the two per-level relin ceremonies).
  const round = await waitFor(
    'committee key',
    async () => {
      const r = await api(`/rounds/${e3Id}`)
      return r.status === 'active' && r.publicKeyAvailable ? r : null
    },
    20 * 60_000,
  )
  report.timings.dkg_wall_secs = Math.round((Date.now() - tRequest) / 1000)
  log(`committee key published in ${report.timings.dkg_wall_secs}s (DKG + 2-level ceremony); applications open until ${new Date(round.inputWindow[1] * 1000).toISOString()}`)
  if (round.inputWindow[1] * 1000 - Date.now() < 60_000) throw new Error('application window too short — raise --window')
  if (JSON.stringify(round.model) !== JSON.stringify(MODEL)) throw new Error(`server model ${JSON.stringify(round.model)} ≠ requested`)
  if (JSON.stringify(round.fixedPointModel) !== JSON.stringify(fixedPoint(MODEL))) throw new Error(`fixed-point model ${JSON.stringify(round.fixedPointModel)} ≠ ${JSON.stringify(fixedPoint(MODEL))}`)
  if (JSON.stringify(round.applicantAddresses.map((a) => a.toLowerCase())) !== JSON.stringify(APPLICANTS.map((b) => b.address.toLowerCase()))) throw new Error('registered applicant order ≠ snapshot order')

  const applyViaClient = async (applicant, override, modelOverride) => {
    const b = APPLICANTS[applicant]
    await page.goto(`${CLIENT}/rounds/${e3Id}`, { waitUntil: 'load' })
    await page.getByTestId('dev-key').selectOption(String(b.devIndex))
    await page.getByTestId('my-features').waitFor({ timeout: 20_000 })
    const shown = JSON.parse(await page.getByTestId('my-features').innerText())
    if (JSON.stringify(shown) !== JSON.stringify(b.features)) throw new Error(`client shows features ${JSON.stringify(shown)} for ${b.address}`)
    const shownIndex = Number(await page.getByTestId('my-index').innerText())
    if (shownIndex !== applicant) throw new Error(`client shows slot ${shownIndex} for applicant ${applicant}`)
    const shownLogit = Number(await page.getByTestId('my-logit').innerText())
    if (Math.abs(shownLogit - linear(b.features)) > 1e-5) throw new Error(`client logit ${shownLogit} ≠ ${linear(b.features)}`)
    if (override) await page.getByTestId('feature-override').fill(JSON.stringify(override))
    if (modelOverride) await page.getByTestId('model-override').fill(JSON.stringify(modelOverride))
    const t0 = Date.now()
    await page.getByTestId('apply-submit').click()
    await Promise.race([
      page.getByTestId('apply-verified').waitFor({ timeout: 600_000 }),
      page.getByTestId('apply-error').waitFor({ timeout: 600_000 }),
    ])
    const error = (await page.getByTestId('apply-error').count()) ? await page.getByTestId('apply-error').innerText() : null
    const wall = Date.now() - t0
    if (error) return { error, wall, address: b.address }
    const txText = await page.locator('text=/tx 0x[0-9a-f]+/').first().innerText()
    const txHash = txText.match(/0x[0-9a-fA-F]{64}/)[0]
    const gas = await page.getByTestId('apply-gas').innerText()
    // `apply-timings` sits inside a collapsed <details>: innerText() is empty there, textContent() is not.
    const timings = JSON.parse(await page.getByTestId('apply-timings').textContent())
    return { txHash, gas: Number(gas), timings, wall, address: b.address }
  }

  // 3. Out-of-range feature must FAIL locally (the credit leg's range check) before any proof.
  log(`applicant ${OUT_OF_RANGE.applicant} submits x_3 = ${CAP + 1} (cap ${CAP}) — must fail at proving`)
  const over = await applyViaClient(OUT_OF_RANGE.applicant, OUT_OF_RANGE.features)
  if (!over.error || !/exceeds the cap/.test(over.error)) throw new Error(`out-of-range feature did NOT fail as expected: ${JSON.stringify(over)}`)
  log(`  ✔ rejected client-side in ${over.wall} ms: "${over.error}"`)
  report.outOfRange = over

  // 4. Three real applications through the client.
  for (const a of APPLY) {
    log(`applicant ${a} (${APPLICANTS[a].address}) applies via the client…`)
    const r = await applyViaClient(a)
    if (r.error) throw new Error(`application by applicant ${a} failed: ${r.error}`)
    report.txs.push({ applicant: a, address: r.address, txHash: r.txHash, gas: r.gas, wall_ms: r.wall, timings: r.timings })
    const pm = r.timings.proveMs
    log(`  ✔ tx ${r.txHash} gas ${r.gas} — encrypt ${Math.round(r.timings.encryptMs)} ms, prove app/ct1Z/ct0Z/ct1M/ct0M ${Math.round(pm.app)}/${Math.round(pm.ct1Z)}/${Math.round(pm.ct0Z)}/${Math.round(pm.ct1M)}/${Math.round(pm.ct0M)} ms, total ${r.wall} ms`)
  }
  const indexed = await waitFor('3 applications indexed', async () => {
    const r = await api(`/rounds/${e3Id}`)
    return r.applications.length >= 3 && r.applications.every((x) => x.ciphertextAvailable) ? r : null
  }, 60_000, 2000)
  log(`server indexed ${indexed.applications.length} applications, all ciphertext pairs recovered from calldata`)
  for (const a of APPLY) {
    const app = indexed.applications.find((x) => x.publisher.toLowerCase() === APPLICANTS[a].address.toLowerCase())
    if (!app || app.index !== a) throw new Error(`applicant ${a} indexed at slot ${app?.index}`)
  }

  // 4b. Wrong model: a genuine applicant proves under a DIFFERENT model (five valid proofs!) —
  //     the contract compares the validity leg's model words to the registered ones → WrongModel.
  log(`applicant ${WRONG_MODEL_APPLICANT} applies under a different model (bias ${WRONG_MODEL.bias}) — the contract must reject it`)
  const wrongModel = await applyViaClient(WRONG_MODEL_APPLICANT, undefined, WRONG_MODEL)
  if (!wrongModel.error || !/WrongModel/.test(wrongModel.error)) throw new Error(`wrong-model application did NOT revert with WrongModel: ${JSON.stringify(wrongModel)}`)
  log(`  ✔ rejected on-chain (simulation) in ${wrongModel.wall} ms: WrongModel`)
  report.wrongModel = { error: wrongModel.error.slice(0, 200), wall: wrongModel.wall }

  // 5. Wrong root + replay, both from applicant #0's own wallet with its accepted calldata.
  {
    const publicClient = createPublicClient({ transport: http(RPC) })
    const first = report.txs[0]
    const tx = await publicClient.getTransaction({ hash: first.txHash })
    const account = privateKeyToAccount(APPLICANTS[first.applicant].key)
    const wallet = createWalletClient({ account, transport: http(RPC) })

    // 5a. Patch the app leg's merkle_root public input → WrongRoot (checked before proof verification).
    const { args: [txE3Id, data] } = decodeFunctionData({ abi: PROGRAM_ABI, data: tx.input })
    const env = decodeAbiParameters(ENVELOPE, data)
    const appPub = [...env[11]]
    appPub[2] = `0x${'ab'.repeat(32)}`
    const badData = encodeFunctionData({ abi: PROGRAM_ABI, functionName: 'publishInput', args: [txE3Id, encodeAbiParameters(ENVELOPE, [...env.slice(0, 11), appPub])] })
    let wrongRoot = null
    try {
      await publicClient.call({ account, to: tx.to, data: badData, gas: 29_000_000n })
    } catch (e) {
      wrongRoot = revertOf(e)
    }
    if (!wrongRoot) throw new Error('wrong-root envelope did NOT revert')
    if (wrongRoot.errorName !== 'WrongRoot') throw new Error(`wrong-root reverted with ${wrongRoot.errorName}, expected WrongRoot`)
    report.wrongRoot = { errorName: wrongRoot.errorName, args: wrongRoot.args?.map(String) }
    log(`  ✔ wrong-root envelope reverted: WrongRoot(${wrongRoot.args.map(String).join(', ')})`)

    // 5b. Replay the exact accepted calldata → AlreadyApplied (simulate, then mine for on-chain evidence).
    let reverted = null
    try {
      await publicClient.call({ account, to: tx.to, data: tx.input, gas: 29_000_000n })
    } catch (e) {
      reverted = revertOf(e)
    }
    if (!reverted) throw new Error('replay of an accepted application did NOT revert')
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
    if (reverted.errorName !== 'AlreadyApplied') throw new Error(`replay reverted with ${reverted.errorName}, expected AlreadyApplied`)
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
      log(`application window closed (chain time +${jump}s)`)
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

  // 7. Assertions on the opened output (one slot per REGISTERED applicant; empty slots open as 0.5).
  const opened = finished.results.opened
  log(`opened (masked) values: ${JSON.stringify(opened)}`)
  if (opened.length !== APPLICANTS.length) throw new Error(`expected ${APPLICANTS.length} opened slots, got ${opened.length}`)
  const trueScores = APPLY.map((a) => sigmoidCubic(linear(APPLICANTS[a].features)))
  for (const a of APPLY) {
    for (const [k, s] of trueScores.entries()) {
      if (Math.abs(opened[a] - s) < 0.5) throw new Error(`opened[${a}] = ${opened[a]} is within 0.5 of true score #${k} = ${s} — the mask does not hide the score`)
    }
  }
  for (const i of [1, 3]) {
    if (Math.abs(opened[i] - 0.5) > 1e-2) throw new Error(`empty slot ${i} opened as ${opened[i]}, expected σ(0) = 0.5`)
  }
  log('  ✔ every opened raw value is > 0.5 away from every true score (meaningless without the masks); empty slots open as 0.5')

  // Each applicant's browser (same context → same localStorage mask) recovers its own score.
  for (const a of APPLY) {
    const b = APPLICANTS[a]
    await page.goto(`${CLIENT}/rounds/${e3Id}`, { waitUntil: 'load' })
    await page.getByTestId('dev-key').selectOption(String(b.devIndex))
    await page.getByTestId('my-score').waitFor({ timeout: 30_000 })
    const shownOpened = Number(await page.getByTestId('my-opened').innerText())
    const shownProb = Number(await page.getByTestId('my-probability').innerText())
    const z = linear(b.features)
    const p = sigmoidCubic(z)
    if (Math.abs(shownOpened - opened[a]) > 1e-3) throw new Error(`applicant ${a}: page shows opened ${shownOpened}, server ${opened[a]}`)
    if (Math.abs(shownProb - p) > 1e-2) throw new Error(`applicant ${a}: recovered σ = ${shownProb}, expected σ_cubic(${z}) = ${p}`)
    report.recovered.push({ applicant: a, address: b.address, index: a, opened: opened[a], logit: z, probability: shownProb, expectedProbability: p })
    log(`  ✔ applicant ${a}: opened ${opened[a].toFixed(4)} − mask → σ ${shownProb.toFixed(6)} (network-computed; local σ_cubic(${z.toFixed(4)}) = ${p.toFixed(6)})`)
  }
  await page.screenshot({ path: '/tmp/ckks-credit-results.png', fullPage: true })

  report.e3Id = e3Id
  report.opened = opened
  writeFileSync(REPORT, JSON.stringify(report, null, 2))
  log(`REPORT written to ${REPORT}`)
  await browser.close()
  console.log('\nCKKS CREDIT SCORING E2E PASSED')
}

main().catch((e) => {
  console.error('\nE2E FAILED:', e)
  writeFileSync(REPORT, JSON.stringify({ ...report, failed: String(e.message ?? e) }, null, 2))
  process.exit(1)
})
