// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Live end-to-end driver for the CKKS private-matching app (CRISP `test_e2e.sh` shape). Expects
// the stack booted by `scripts/dev.sh` (anvil + contracts + 5 ciphernodes + server :8093 + client :5176).
//
// Drives the REAL client in headless Chrome (playwright): opens a round for two parties (anvil #6 =
// A, #7 = B, registered on-chain), waits for the committee key (ParamSet 5: DKG + the level-0 relin
// ceremony), then for each party selects the dev wallet in the navbar and clicks "Encrypt … + mask,
// prove 5 legs & submit" — the page cap-normalises the profile vector, samples a cross-term mask,
// coefficient-encodes (forward for A, reversed for B) + encrypts BOTH in WASM, generates the five
// UltraHonk proofs and sends the wallet transaction. Asserts:
//
//   1. an OUT-OF-RANGE entry (|v| > 1 after normalisation) fails at proving (client-side pre-check);
//   2. a WRONG-LAYOUT submission (A proving the reversed layout, five valid proofs!) reverts with
//      WrongRole on simulation;
//   3. both genuine submissions are accepted on-chain (SubmissionPublished, 5 Honk verifies each);
//   4. a REPLAY of an accepted envelope reverts (AlreadySubmitted: one submission per party) and a
//      patched `role` word reverts with WrongRole;
//   5. the server evaluates as soon as both are in → publish → threshold decrypt; the opened score
//      equals the fixed-point dot product ⟨a, b⟩ within 1e-2, and every OPENED cross-term coefficient
//      (1..63) is > 1 away from the true a_i·b_j products (the masks hide them).
//
//   node scripts/e2e.mjs [--client http://127.0.0.1:5176] [--api http://127.0.0.1:8093] [--window 600]
//   CHROME_BIN=... to pin the Chrome binary (playwright 1.52 wants chromium-1169).

import { writeFileSync } from 'node:fs'
import { chromium } from 'playwright'
import { createPublicClient, createWalletClient, decodeAbiParameters, decodeErrorResult, decodeFunctionData, encodeAbiParameters, encodeFunctionData, http, parseAbi, parseAbiParameters } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'

const args = process.argv.slice(2)
const opt = (n, d) => (args.includes(n) ? args[args.indexOf(n) + 1] : d)
const CLIENT = opt('--client', 'http://127.0.0.1:5176')
const API = opt('--api', 'http://127.0.0.1:8093')
const RPC = opt('--rpc', 'http://127.0.0.1:8545')
const WINDOW_SECS = Number(opt('--window', '600'))
const REPORT = opt('--report', '/tmp/ckks-matching-e2e-report.json')

const K = 16
const CAP = 100
// The two parties = client DEV_KEYS[0..1] (anvil #6 = A, #7 = B) with the client's DEMO vectors.
const PARTIES = [
  { key: '0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e', raw: [50, -25, 100, -100, 12.5, 0, 75, -50, 30, -70, 90, -10, 60, 20, -40, 5], devIndex: 0, role: 'a' },
  { key: '0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356', raw: [40, 30, -20, 90, -100, 100, 10, 50, -60, 80, 25, 75, -35, 15, 95, -5], devIndex: 1, role: 'b' },
].map((p) => ({ ...p, address: privateKeyToAccount(p.key).address }))
const OUT_OF_RANGE = [50, -25, 100, -100, 12.5, 0, 75, -50, 30, -70, 90, -10, 60, 20, -40, 150] // 1.5 after /cap

// The fixed point EXACTLY as the circuit pins it (× 2^16).
const fp = (v) => Math.round((v / CAP) * 65536) / 65536
const expectedScore = () => {
  let acc = 0
  for (let j = 0; j < K; j++) acc += fp(PARTIES[0].raw[j]) * fp(PARTIES[1].raw[j])
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
  'error AlreadySubmitted(uint256 e3Id, address party)',
  'error WrongSender(address proven, address sender)',
  'error WrongIndex(uint256 got, uint256 want)',
  'error WrongRole(uint256 got, uint256 want)',
  'error NotRegistered(uint256 e3Id, address party)',
  'error RoundNotRegistered(uint256 e3Id)',
  'error UCommitmentMismatch(uint256 ciphertext, bytes32 ct0Leg, bytes32 ct1Leg)',
  'error MCommitmentMismatch(uint256 ciphertext, bytes32 ct0Leg, bytes32 appLeg)',
  'error Ct0ProofInvalid(uint256 ciphertext)',
  'error Ct1ProofInvalid(uint256 ciphertext)',
  'error AppProofInvalid()',
])
// The contract's `abi.decode(data, (MatchingSubmission))`: ONE nested tuple.
const ENVELOPE = parseAbiParameters(
  '((bytes, bytes, bytes32[], bytes, bytes32[]), (bytes, bytes, bytes32[], bytes, bytes32[]), bytes, bytes32[])',
)

const report = { txs: [], timings: {} }

async function main() {
  const status = await api('/status')
  log(`server ok: program ${status.programAddress}, chain ${status.chainId} block ${status.block}, ParamSet ${status.paramSet}, k ${status.k}`)

  const browser = await chromium.launch({ headless: true, executablePath: process.env.CHROME_BIN || undefined })
  const context = await browser.newContext()
  const page = await context.newPage()
  page.on('console', (m) => {
    if (m.type() === 'error') console.error('  [browser]', m.text())
  })
  page.on('pageerror', (e) => console.error('  [pageerror]', e.message))

  // 1. Open a round THROUGH THE CLIENT (Rounds page → party A / party B → Request round).
  const tRequest = Date.now()
  await page.goto(`${CLIENT}/rounds`, { waitUntil: 'load' })
  await page.getByTestId('party-a').fill(PARTIES[0].address)
  await page.getByTestId('party-b').fill(PARTIES[1].address)
  await page.getByTestId('duration').fill(String(WINDOW_SECS))
  await page.getByTestId('open-round').click()
  await page.waitForFunction(() => document.body.innerText.includes('requested'), null, { timeout: 120_000 })
  const rounds = await api('/rounds')
  const e3Id = rounds[0].e3Id
  log(`round #${e3Id} requested via the client ([A, B] registered on-chain)`)

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
  if (round.inputWindow[1] * 1000 - Date.now() < 60_000) throw new Error('submission window too short — raise --window')
  if (JSON.stringify(round.parties.map((a) => a.toLowerCase())) !== JSON.stringify(PARTIES.map((p) => p.address.toLowerCase()))) throw new Error('registered party order ≠ [A, B]')

  const submitViaClient = async (party, rawOverride, roleOverride) => {
    const p = PARTIES[party]
    await page.goto(`${CLIENT}/rounds/${e3Id}`, { waitUntil: 'load' })
    await page.getByTestId('dev-key').selectOption(String(p.devIndex))
    await page.getByTestId('my-role').waitFor({ timeout: 20_000 })
    const shownRole = (await page.getByTestId('my-role').innerText()).toLowerCase()
    if (shownRole !== p.role) throw new Error(`client shows role ${shownRole} for party ${party}`)
    const shownIndex = Number(await page.getByTestId('my-index').innerText())
    if (shownIndex !== party) throw new Error(`client shows slot ${shownIndex} for party ${party}`)
    await page.getByTestId('vector').fill(JSON.stringify(rawOverride ?? p.raw))
    await page.getByTestId('cap').fill(String(CAP))
    if (roleOverride) await page.getByTestId('role-override').selectOption(roleOverride)
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

  // 3. Out-of-range entry must FAIL locally (the matching leg's range check) before any proof.
  log(`party A submits an entry of 150 (cap ${CAP} → 1.5) — must fail at proving`)
  const over = await submitViaClient(0, OUT_OF_RANGE)
  if (!over.error || !/outside \[-1, 1\]/.test(over.error)) throw new Error(`out-of-range entry did NOT fail as expected: ${JSON.stringify(over)}`)
  log(`  ✔ rejected client-side in ${over.wall} ms: "${over.error}"`)
  report.outOfRange = over

  // 3b. Wrong layout: party A proves the REVERSED layout (five valid proofs!) — the contract
  //     compares the validity leg's `role` word to the registered slot → WrongRole.
  log('party A proves the reversed layout (role B) — the contract must reject it')
  const wrongRole = await submitViaClient(0, undefined, 'b')
  if (!wrongRole.error || !/WrongRole|does not match role/.test(wrongRole.error)) throw new Error(`wrong-layout submission did NOT fail with WrongRole: ${JSON.stringify(wrongRole)}`)
  log(`  ✔ rejected in ${wrongRole.wall} ms: ${wrongRole.error.slice(0, 120)}`)
  report.wrongRole = { error: wrongRole.error.slice(0, 200), wall: wrongRole.wall }

  // 4. Both genuine submissions through the client.
  for (const party of [0, 1]) {
    log(`party ${PARTIES[party].role.toUpperCase()} (${PARTIES[party].address}) submits via the client…`)
    const r = await submitViaClient(party)
    if (r.error) throw new Error(`submission by party ${party} failed: ${r.error}`)
    report.txs.push({ party, address: r.address, txHash: r.txHash, gas: r.gas, wall_ms: r.wall, timings: r.timings })
    const pm = r.timings.proveMs
    log(`  ✔ tx ${r.txHash} gas ${r.gas} — encrypt ${Math.round(r.timings.encryptMs)} ms, prove app/ct1V/ct0V/ct1M/ct0M ${Math.round(pm.app)}/${Math.round(pm.ct1V)}/${Math.round(pm.ct0V)}/${Math.round(pm.ct1M)}/${Math.round(pm.ct0M)} ms, total ${r.wall} ms`)
  }
  const indexed = await waitFor('2 submissions indexed', async () => {
    const r = await api(`/rounds/${e3Id}`)
    return r.submissions.length >= 2 && r.submissions.every((x) => x.ciphertextAvailable) ? r : null
  }, 60_000, 2000)
  log(`server indexed ${indexed.submissions.length} submissions, both ciphertext pairs recovered from calldata`)
  for (const party of [0, 1]) {
    const s = indexed.submissions.find((x) => x.publisher.toLowerCase() === PARTIES[party].address.toLowerCase())
    if (!s || s.index !== party || s.role !== PARTIES[party].role) throw new Error(`party ${party} indexed at slot ${s?.index} role ${s?.role}`)
  }

  // 5. Patched role word + replay, both from party A's own wallet with its accepted calldata.
  {
    const publicClient = createPublicClient({ transport: http(RPC) })
    const first = report.txs[0]
    const tx = await publicClient.getTransaction({ hash: first.txHash })
    const account = privateKeyToAccount(PARTIES[first.party].key)
    const wallet = createWalletClient({ account, transport: http(RPC) })

    // 5a. Patch the app leg's `role` public input → WrongRole (checked before proof verification).
    const { args: [txE3Id, data] } = decodeFunctionData({ abi: PROGRAM_ABI, data: tx.input })
    const [env] = decodeAbiParameters(ENVELOPE, data)
    const appPub = [...env[3]]
    appPub[0] = `0x${'00'.repeat(31)}01`
    const badData = encodeFunctionData({ abi: PROGRAM_ABI, functionName: 'publishInput', args: [txE3Id, encodeAbiParameters(ENVELOPE, [[env[0], env[1], env[2], appPub]])] })
    let patched = null
    try {
      await publicClient.call({ account, to: tx.to, data: badData, gas: 29_000_000n })
    } catch (e) {
      patched = revertOf(e)
    }
    if (!patched) throw new Error('patched-role envelope did NOT revert')
    if (!['WrongRole', 'AlreadySubmitted'].includes(patched.errorName)) throw new Error(`patched-role reverted with ${patched.errorName}, expected WrongRole`)
    report.patchedRole = { errorName: patched.errorName, args: patched.args?.map(String) }
    log(`  ✔ patched-role envelope reverted: ${patched.errorName}(${patched.args?.map(String).join(', ') ?? ''})`)

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

  // 6. Both parties are in: the server evaluates right away ("Evaluate now" is the manual fallback)
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

  // 7. Assertions on the opened output: score = −c_0 = ⟨a, b⟩; cross terms hidden.
  const { score, opened } = finished.results
  const want = expectedScore()
  log(`opened c_0 = ${opened[0]} → score ${score} (expected ⟨a, b⟩ = ${want.toFixed(6)})`)
  if (opened.length !== 64) throw new Error(`expected 64 opened coefficients, got ${opened.length}`)
  if (Math.abs(score - want) > 1e-2) throw new Error(`score ${score} ≠ expected ${want}`)
  if (Math.abs(score + opened[0]) > 1e-9) throw new Error('score is not −opened[0]')
  // Cross terms on coefficients 1..: forward a_i sits on i+1, reversed b_j on N−j−1, so the product
  // lands on N+i−j ≡ −t^(i−j) — coefficient k (1 ≤ k < K) is −Σ_{i−j=k} a_i b_j (|·| ≤ 16), plus
  // m_a + m_b (uniform in [0, 2048)). With the masks they must not sit near the unmasked value.
  const cross = (k) => {
    let acc = 0
    for (let i = 0; i < K; i++) {
      const j = i - k
      if (j >= 0 && j < K) acc -= fp(PARTIES[0].raw[i]) * fp(PARTIES[1].raw[j])
    }
    return acc
  }
  let hidden = 0
  for (let k = 1; k < 32; k++) {
    if (Math.abs(opened[k] - cross(k)) > 1) hidden++
  }
  if (hidden < 28) throw new Error(`only ${hidden}/31 cross-term coefficients are masked away from their plaintext value`)
  log(`  ✔ score matches the fixed-point dot product within 1e-2; ${hidden}/31 cross-term coefficients are mask-hidden`)

  // Both parties' browsers show the same score.
  for (const party of [0, 1]) {
    const p = PARTIES[party]
    await page.goto(`${CLIENT}/rounds/${e3Id}`, { waitUntil: 'load' })
    await page.getByTestId('dev-key').selectOption(String(p.devIndex))
    await page.getByTestId('score').waitFor({ timeout: 30_000 })
    const shown = Number((await page.getByTestId('score').innerText()).match(/-?\d+(\.\d+)?/)[0])
    if (Math.abs(shown - score) > 1e-3) throw new Error(`party ${party}: page shows score ${shown}, server ${score}`)
    log(`  ✔ party ${p.role.toUpperCase()} sees score ${shown.toFixed(4)}`)
  }
  await page.screenshot({ path: '/tmp/ckks-matching-results.png', fullPage: true })

  report.e3Id = e3Id
  report.score = score
  report.expectedScore = want
  report.opened = opened
  writeFileSync(REPORT, JSON.stringify(report, null, 2))
  log(`REPORT written to ${REPORT}`)
  await browser.close()
  console.log('\nCKKS PRIVATE MATCHING E2E PASSED')
}

main().catch((e) => {
  console.error('\nE2E FAILED:', e)
  writeFileSync(REPORT, JSON.stringify({ ...report, failed: String(e.message ?? e) }, null, 2))
  process.exit(1)
})
