// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Live end-to-end driver for the CKKS treasury-risk app (CRISP `test_e2e.sh` shape). Expects
// the stack booted by `scripts/dev.sh` (anvil + contracts + 5 ciphernodes + server :8094 + client :5177).
//
// Drives the REAL client in headless Chrome (playwright): opens a round with the fixture weights
// and three DAOs (anvil #6, #7, #8, registered on-chain), waits for the committee key (ParamSet 5:
// DKG + the level-0 relin ceremony), then for each DAO selects the dev wallet in the navbar and
// clicks "Encrypt … prove 7 legs & submit" — the page cap-normalises the exposures, samples a
// cross-term mask, coefficient-encodes forward(x) / reversed(w∘x) / mask(m) + encrypts all THREE
// in WASM, generates the seven UltraHonk proofs and sends the wallet transaction. Asserts:
//
//   1. an OUT-OF-RANGE exposure (> 1 after normalisation) fails at proving (client-side pre-check);
//   2. a WRONG-WEIGHTS submission (seven valid proofs under nudged weights!) reverts with
//      WrongWeights on simulation;
//   3. all three genuine submissions are accepted on-chain (SubmissionPublished, 7 Honk verifies each);
//   4. a REPLAY of an accepted envelope reverts (AlreadySubmitted: one submission per DAO) and a
//      patched weight word reverts with WrongWeights;
//   5. the server evaluates as soon as every DAO is in → publish → threshold decrypt; the opened
//      risk equals the fixed-point Σ_a w_a (Σ_i x_{i,a})² within 1e-2, and every OPENED cross-term
//      coefficient (1..31) is > 1 away from its unmasked value (the masks hide them).
//
//   node scripts/e2e.mjs [--client http://127.0.0.1:5177] [--api http://127.0.0.1:8094] [--window 600]
//   CHROME_BIN=... to pin the Chrome binary (playwright 1.52 wants chromium-1169).

import { writeFileSync } from 'node:fs'
import { chromium } from 'playwright'
import { createPublicClient, createWalletClient, decodeAbiParameters, decodeErrorResult, decodeFunctionData, encodeAbiParameters, encodeFunctionData, http, parseAbi, parseAbiParameters } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'

const args = process.argv.slice(2)
const opt = (n, d) => (args.includes(n) ? args[args.indexOf(n) + 1] : d)
const CLIENT = opt('--client', 'http://127.0.0.1:5177')
const API = opt('--api', 'http://127.0.0.1:8094')
const RPC = opt('--rpc', 'http://127.0.0.1:8545')
const WINDOW_SECS = Number(opt('--window', '600'))
const REPORT = opt('--report', '/tmp/ckks-treasury-e2e-report.json')

const ASSETS = 4
const CAP = 100
const WEIGHTS = [0.5, -0.25, 1.0, 0.125]
// The three DAOs = client DEV_KEYS[0..2] (anvil #6, #7, #8) with the client's DEMO books.
const DAOS = [
  { key: '0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e', raw: [30, 10, 45, 15], devIndex: 0 },
  { key: '0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356', raw: [20, 10, 0, 10], devIndex: 1 },
  { key: '0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97', raw: [5, 40, 25, 30], devIndex: 2 },
].map((p) => ({ ...p, address: privateKeyToAccount(p.key).address }))
const OUT_OF_RANGE = [30, 10, 150, 15] // 1.5 after /cap

// The fixed point EXACTLY as the circuit pins it (× 2^16).
const fp = (v) => Math.round(v * 65536) / 65536
const fpX = (raw) => fp(raw / CAP)
const expectedRisk = () => {
  const agg = new Array(ASSETS).fill(0)
  for (const d of DAOS) for (let a = 0; a < ASSETS; a++) agg[a] += fpX(d.raw[a])
  let acc = 0
  for (let a = 0; a < ASSETS; a++) acc += fp(WEIGHTS[a]) * agg[a] * agg[a]
  return acc
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
  'error AlreadySubmitted(uint256 e3Id, address dao)',
  'error WrongSender(address proven, address sender)',
  'error WrongIndex(uint256 got, uint256 want)',
  'error WrongWeights(uint256 word, bytes32 got, bytes32 want)',
  'error NotRegistered(uint256 e3Id, address dao)',
  'error RoundNotRegistered(uint256 e3Id)',
  'error UCommitmentMismatch(uint256 ciphertext, bytes32 ct0Leg, bytes32 ct1Leg)',
  'error MCommitmentMismatch(uint256 ciphertext, bytes32 ct0Leg, bytes32 appLeg)',
  'error Ct0ProofInvalid(uint256 ciphertext)',
  'error Ct1ProofInvalid(uint256 ciphertext)',
  'error AppProofInvalid()',
])
// The contract's `abi.decode(data, (TreasurySubmission))`: ONE nested tuple.
const ENVELOPE = parseAbiParameters(
  '((bytes, bytes, bytes32[], bytes, bytes32[]), (bytes, bytes, bytes32[], bytes, bytes32[]), (bytes, bytes, bytes32[], bytes, bytes32[]), bytes, bytes32[])',
)

const report = { txs: [], timings: {} }

async function main() {
  const status = await api('/status')
  log(`server ok: program ${status.programAddress}, chain ${status.chainId} block ${status.block}, ParamSet ${status.paramSet}, assets ${status.assets}, minDaos ${status.minDaos}`)

  const browser = await chromium.launch({ headless: true, executablePath: process.env.CHROME_BIN || undefined })
  const context = await browser.newContext()
  const page = await context.newPage()
  page.on('console', (m) => {
    if (m.type() === 'error') console.error('  [browser]', m.text())
  })
  page.on('pageerror', (e) => console.error('  [pageerror]', e.message))

  // 1. Open a round THROUGH THE CLIENT (Rounds page → weights / DAOs → Request round).
  const tRequest = Date.now()
  await page.goto(`${CLIENT}/rounds`, { waitUntil: 'load' })
  for (let a = 0; a < ASSETS; a++) await page.getByTestId(`weight-${a}`).fill(String(WEIGHTS[a]))
  await page.getByTestId('daos').fill(DAOS.map((d) => d.address).join('\n'))
  await page.getByTestId('duration').fill(String(WINDOW_SECS))
  await page.getByTestId('open-round').click()
  await page.waitForFunction(() => document.body.innerText.includes('requested'), null, { timeout: 120_000 })
  const rounds = await api('/rounds')
  const e3Id = rounds[0].e3Id
  log(`round #${e3Id} requested via the client (weights + ${DAOS.length} DAOs registered on-chain)`)

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
  log(`committee key published in ${report.timings.dkg_wall_secs}s (DKG + level-0 ceremony); submissions open until ${new Date(round.inputWindow[1] * 1000).toISOString()}`)
  if (round.inputWindow[1] * 1000 - Date.now() < 90_000) throw new Error('submission window too short — raise --window')
  if (JSON.stringify(round.daos.map((a) => a.toLowerCase())) !== JSON.stringify(DAOS.map((p) => p.address.toLowerCase()))) throw new Error('registered DAO order ≠ [6, 7, 8]')
  if (JSON.stringify(round.weightsFixed) !== JSON.stringify([32768, -16384, 65536, 8192])) throw new Error(`registered weights ${JSON.stringify(round.weightsFixed)} ≠ fixture`)

  const submitViaClient = async (dao, rawOverride, wrongWeights = false) => {
    const p = DAOS[dao]
    await page.goto(`${CLIENT}/rounds/${e3Id}`, { waitUntil: 'load' })
    await page.getByTestId('dev-key').selectOption(String(p.devIndex))
    await page.getByTestId('my-index').waitFor({ timeout: 20_000 })
    const shownIndex = Number(await page.getByTestId('my-index').innerText())
    if (shownIndex !== dao) throw new Error(`client shows slot ${shownIndex} for DAO ${dao}`)
    const raw = rawOverride ?? p.raw
    for (let a = 0; a < ASSETS; a++) await page.getByTestId(`exposure-${a}`).fill(String(raw[a]))
    await page.getByTestId('cap').fill(String(CAP))
    if (wrongWeights) await page.getByTestId('wrong-weights').check()
    const t0 = Date.now()
    await page.getByTestId('submit').click()
    await Promise.race([
      page.getByTestId('submit-verified').waitFor({ timeout: 600_000 }),
      page.getByTestId('submit-error').waitFor({ timeout: 600_000 }),
    ])
    const error = (await page.getByTestId('submit-error').count()) ? await page.getByTestId('submit-error').innerText() : null
    const wall = Date.now() - t0
    if (error) return { error, wall, address: p.address }
    const txText = await page.locator('text=/tx 0x[0-9a-f]+/').first().innerText()
    const txHash = txText.match(/0x[0-9a-fA-F]{64}/)[0]
    const gas = await page.getByTestId('submit-gas').innerText()
    // `submit-timings` sits inside a collapsed <details>: innerText() is empty there, textContent() is not.
    const timings = JSON.parse(await page.getByTestId('submit-timings').textContent())
    return { txHash, gas: Number(gas), timings, wall, address: p.address }
  }

  // 3. Out-of-range exposure must FAIL locally (the treasury leg's range check) before any proof.
  log(`DAO 0 submits an exposure of 150 (cap ${CAP} → 1.5) — must fail at proving`)
  const over = await submitViaClient(0, OUT_OF_RANGE)
  if (!over.error || !/outside \[0, 1\]/.test(over.error)) throw new Error(`out-of-range exposure did NOT fail as expected: ${JSON.stringify(over)}`)
  log(`  ✔ rejected client-side in ${over.wall} ms: "${over.error}"`)
  report.outOfRange = over

  // 3b. Wrong weights: DAO 0 proves under nudged weights (seven valid proofs!) — the contract
  //     compares the validity leg's weight words to the registered ones → WrongWeights.
  log('DAO 0 proves under the wrong weights — the contract must reject it')
  const wrongW = await submitViaClient(0, undefined, true)
  if (!wrongW.error || !/WrongWeights/.test(wrongW.error)) throw new Error(`wrong-weights submission did NOT fail with WrongWeights: ${JSON.stringify(wrongW)}`)
  log(`  ✔ rejected in ${wrongW.wall} ms: ${wrongW.error.slice(0, 120)}`)
  report.wrongWeights = { error: wrongW.error.slice(0, 200), wall: wrongW.wall }

  // 4. All genuine submissions through the client.
  for (const dao of DAOS.keys()) {
    log(`DAO ${dao} (${DAOS[dao].address}) submits via the client…`)
    const r = await submitViaClient(dao)
    if (r.error) throw new Error(`submission by DAO ${dao} failed: ${r.error}`)
    report.txs.push({ dao, address: r.address, txHash: r.txHash, gas: r.gas, wall_ms: r.wall, timings: r.timings })
    const pm = r.timings.proveMs
    log(`  ✔ tx ${r.txHash} gas ${r.gas} — encrypt ${Math.round(r.timings.encryptMs)} ms, prove app/F/R/M ${Math.round(pm.app)}/${Math.round(pm.ct0F + pm.ct1F)}/${Math.round(pm.ct0R + pm.ct1R)}/${Math.round(pm.ct0M + pm.ct1M)} ms, total ${r.wall} ms`)
  }
  const indexed = await waitFor(`${DAOS.length} submissions indexed`, async () => {
    const r = await api(`/rounds/${e3Id}`)
    return r.submissions.length >= DAOS.length && r.submissions.every((x) => x.ciphertextAvailable) ? r : null
  }, 60_000, 2000)
  log(`server indexed ${indexed.submissions.length} submissions, every ciphertext triple recovered from calldata`)
  for (const dao of DAOS.keys()) {
    const s = indexed.submissions.find((x) => x.publisher.toLowerCase() === DAOS[dao].address.toLowerCase())
    if (!s || s.index !== dao) throw new Error(`DAO ${dao} indexed at slot ${s?.index}`)
  }

  // 5. Patched weight word + replay, both from DAO 0's own wallet with its accepted calldata.
  {
    const publicClient = createPublicClient({ transport: http(RPC) })
    const first = report.txs[0]
    const tx = await publicClient.getTransaction({ hash: first.txHash })
    const account = privateKeyToAccount(DAOS[first.dao].key)
    const wallet = createWalletClient({ account, transport: http(RPC) })

    // 5a. Patch the app leg's `w_1` public input → WrongWeights (checked before proof verification).
    const { args: [txE3Id, data] } = decodeFunctionData({ abi: PROGRAM_ABI, data: tx.input })
    const [env] = decodeAbiParameters(ENVELOPE, data)
    const appPub = [...env[4]]
    appPub[1] = `0x${(BigInt(appPub[1]) + 1n).toString(16).padStart(64, '0')}`
    const badData = encodeFunctionData({ abi: PROGRAM_ABI, functionName: 'publishInput', args: [txE3Id, encodeAbiParameters(ENVELOPE, [[env[0], env[1], env[2], env[3], appPub]])] })
    let patched = null
    try {
      await publicClient.call({ account, to: tx.to, data: badData, gas: 29_000_000n })
    } catch (e) {
      patched = revertOf(e)
    }
    if (!patched) throw new Error('patched-weight envelope did NOT revert')
    if (!['WrongWeights', 'AlreadySubmitted'].includes(patched.errorName)) throw new Error(`patched-weight reverted with ${patched.errorName}, expected WrongWeights`)
    report.patchedWeight = { errorName: patched.errorName, args: patched.args?.map(String) }
    log(`  ✔ patched-weight envelope reverted: ${patched.errorName}(${patched.args?.map(String).join(', ') ?? ''})`)

    // 5b. Replay the exact accepted calldata → AlreadySubmitted (simulate, then mine for on-chain evidence).
    let reverted = null
    try {
      await publicClient.call({ account, to: tx.to, data: tx.input, gas: 29_000_000n })
    } catch (e) {
      reverted = revertOf(e)
    }
    if (!reverted) throw new Error('replay of an accepted submission did NOT revert')
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

  // 6. Every DAO is in: the server evaluates right away ("Evaluate now" is the manual fallback)
  //    → publish → threshold decryption → results.
  const tEval = Date.now()
  const hooked = await waitFor('auto-evaluation', async () => {
    const r = await api(`/rounds/${e3Id}`)
    return r.status !== 'active' ? r : null
  }, 90_000, 3000).catch(() => null)
  if (!hooked) {
    log('auto-evaluation did not fire within 90 s — clicking "Evaluate now"')
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

  // 7. Assertions on the opened output: risk = −c_0 = Σ_a w_a (Σ_i x_{i,a})²; cross terms hidden.
  const { risk, opened } = finished.results
  const want = expectedRisk()
  log(`opened c_0 = ${opened[0]} → risk ${risk} (expected ${want.toFixed(6)})`)
  if (opened.length !== 64) throw new Error(`expected 64 opened coefficients, got ${opened.length}`)
  if (Math.abs(risk - want) > 1e-2) throw new Error(`risk ${risk} ≠ expected ${want}`)
  if (Math.abs(risk + opened[0]) > 1e-9) throw new Error('risk is not −opened[0]')
  // Cross terms on coefficients 1..: forward X_a sits on a+1, reversed (w_b X_b) on N−b−1, so the
  // product lands on N+a−b ≡ −t^(a−b) — coefficient k (1 ≤ k < ASSETS) is −Σ_{a−b=k} X_a w_b X_b,
  // plus Σ_i m_{i,k} (each uniform in [0, 1024)). With the masks they must not sit near the unmasked value.
  const agg = new Array(ASSETS).fill(0)
  for (const d of DAOS) for (let a = 0; a < ASSETS; a++) agg[a] += fpX(d.raw[a])
  const cross = (k) => {
    let acc = 0
    for (let a = 0; a < ASSETS; a++) {
      const b = a - k
      if (b >= 0 && b < ASSETS) acc -= agg[a] * fp(WEIGHTS[b]) * agg[b]
    }
    return acc
  }
  let hidden = 0
  for (let k = 1; k < 32; k++) {
    if (Math.abs(opened[k] - cross(k)) > 1) hidden++
  }
  if (hidden < 28) throw new Error(`only ${hidden}/31 cross-term coefficients are masked away from their plaintext value`)
  log(`  ✔ risk matches the fixed-point oracle within 1e-2; ${hidden}/31 cross-term coefficients are mask-hidden`)

  // Every DAO's browser shows the same risk.
  for (const dao of DAOS.keys()) {
    const p = DAOS[dao]
    await page.goto(`${CLIENT}/rounds/${e3Id}`, { waitUntil: 'load' })
    await page.getByTestId('dev-key').selectOption(String(p.devIndex))
    await page.getByTestId('risk').waitFor({ timeout: 30_000 })
    const shown = Number((await page.getByTestId('risk').innerText()).match(/-?\d+(\.\d+)?/)[0])
    if (Math.abs(shown - risk) > 1e-3) throw new Error(`DAO ${dao}: page shows risk ${shown}, server ${risk}`)
    log(`  ✔ DAO ${dao} sees risk ${shown.toFixed(4)}`)
  }
  await page.screenshot({ path: '/tmp/ckks-treasury-results.png', fullPage: true })

  report.e3Id = e3Id
  report.risk = risk
  report.expectedRisk = want
  report.opened = opened
  writeFileSync(REPORT, JSON.stringify(report, null, 2))
  log(`REPORT written to ${REPORT}`)
  await browser.close()
  console.log('\nCKKS TREASURY RISK E2E PASSED')
}

main().catch((e) => {
  console.error('\nE2E FAILED:', e)
  writeFileSync(REPORT, JSON.stringify({ ...report, failed: String(e.message ?? e) }, null, 2))
  process.exit(1)
})
