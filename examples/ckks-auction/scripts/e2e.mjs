// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Live end-to-end driver for the CKKS auction (CRISP `test_e2e.sh` shape). Expects the stack
// booted by `scripts/dev.sh` (anvil + contracts + 5 ciphernodes + server :8090 + client :5173).
//
// Drives the REAL client in headless Chromium (playwright): opens a round with a 5-address balance
// snapshot, waits for the committee key + the hybrid ceremony key, then for each bidder selects the dev
// wallet in the navbar, types the bid, and clicks "Encrypt, prove & submit" — the page does the
// WASM encryption, the three UltraHonk proofs and the wallet transaction. Asserts:
//
//   1. an OVER-BALANCE bid fails locally before proving (the app leg's predicate);
//   2. four in-balance bids are accepted on-chain (VerifiedInputPublished, 3 Honk verifies);
//   3. a REPLAY of an accepted envelope reverts with DuplicateSubmission;
//   4. after evaluate → publish → threshold decrypt, the winner is the top bid and every opened
//      slot is a saturated ±1 sign.
//
//   node scripts/e2e.mjs [--client http://127.0.0.1:5173] [--api http://127.0.0.1:8090]
//   CHROME_BIN=... to pin the Chrome binary (playwright 1.52 wants chromium-1169).

import { readFileSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium } from 'playwright'
import { createPublicClient, createWalletClient, decodeErrorResult, encodeAbiParameters, http, parseAbi, parseAbiParameters } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'

const here = path.dirname(fileURLToPath(import.meta.url))
const args = process.argv.slice(2)
const opt = (n, d) => (args.includes(n) ? args[args.indexOf(n) + 1] : d)
const CLIENT = opt('--client', 'http://127.0.0.1:5173')
const API = opt('--api', 'http://127.0.0.1:8090')
const RPC = opt('--rpc', 'http://127.0.0.1:8545')
const WINDOW_SECS = Number(opt('--window', '900'))
const REPORT = opt('--report', '/tmp/ckks-auction-e2e-report.json')

// Dev bidders = client DEV_KEYS order (anvil #6, #7, #8, #9, #0) with the default snapshot balances.
const BIDDERS = [
  { key: '0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e', balance: 100, devIndex: 0 },
  { key: '0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356', balance: 500, devIndex: 1 },
  { key: '0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97', balance: 1000, devIndex: 2 },
  { key: '0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6', balance: 1000, devIndex: 3 },
  { key: '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80', balance: 1000, devIndex: 4 },
].map((b) => ({ ...b, address: privateKeyToAccount(b.key).address }))

// Bids (each ≤ the bidder's snapshot balance — the app leg REJECTS over-balance bids):
// #2 (815) wins; #3 (402) vs #4 (382) is a 2% gap the sign map must binarise, not leak.
const BIDS = [
  { bidder: 0, bid: 74 }, // balance 100
  { bidder: 2, bid: 815 },
  { bidder: 3, bid: 402 },
  { bidder: 4, bid: 382 },
]
const OVER_BALANCE = { bidder: 1, bid: 700 } // balance 500

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

const report = { txs: [], timings: {}, browserTimings: {} }

async function main() {
  const snapshot = BIDDERS.map((b) => ({ address: b.address, balance: String(b.balance) }))
  const status = await api('/status')
  log(`server ok: program ${status.programAddress}, chain ${status.chainId} block ${status.block}`)

  const browser = await chromium.launch({ headless: true, executablePath: process.env.CHROME_BIN || undefined })
  const context = await browser.newContext()
  const page = await context.newPage()
  page.on('console', (m) => {
    if (m.type() === 'error') console.error('  [browser]', m.text())
  })
  page.on('pageerror', (e) => console.error('  [pageerror]', e.message))

  // 1. Open a round THROUGH THE CLIENT (Rounds page → snapshot textarea → Request round).
  const tRequest = Date.now()
  await page.goto(`${CLIENT}/rounds`, { waitUntil: 'load' })
  await page.getByTestId('snapshot').fill(JSON.stringify(snapshot))
  await page.getByTestId('duration').fill(String(WINDOW_SECS))
  await page.getByTestId('open-round').click()
  await page.waitForFunction(() => document.body.innerText.includes('requested'), null, { timeout: 120_000 })
  const rounds = await api('/rounds')
  const e3Id = rounds[0].e3Id
  log(`round #${e3Id} requested via the client (balance root set on-chain)`)

  // 2. Wait for the committee key (real DKG over the wide transport) and the ONE hybrid ceremony key.
  const round = await waitFor(
    'committee key + hybrid ceremony key',
    async () => {
      const r = await api(`/rounds/${e3Id}`)
      return r.status === 'active' && r.publicKeyAvailable && r.ceremonyKeys >= r.ceremonyKeysExpected ? r : null
    },
    20 * 60_000,
  )
  report.timings.dkg_and_ceremony_wall_secs = Math.round((Date.now() - tRequest) / 1000)
  log(`committee key published + ${round.ceremonyKeys} ceremony keys in ${report.timings.dkg_and_ceremony_wall_secs}s; bidding open until ${new Date(round.inputWindow[1] * 1000).toISOString()}`)
  if (round.inputWindow[1] * 1000 - Date.now() < 60_000) throw new Error('bidding window too short for the bids — raise E3_DURATION')

  const bidViaClient = async ({ bidder, bid }) => {
    const b = BIDDERS[bidder]
    await page.goto(`${CLIENT}/rounds/${e3Id}`, { waitUntil: 'load' })
    await page.getByTestId('dev-key').selectOption(String(b.devIndex))
    await page.getByTestId('my-balance').waitFor({ timeout: 20_000 })
    const shown = await page.getByTestId('my-balance').innerText()
    if (Number(shown) !== b.balance) throw new Error(`client shows balance ${shown} for ${b.address}, expected ${b.balance}`)
    await page.getByTestId('bid-input').fill(String(bid))
    const t0 = Date.now()
    await page.getByTestId('bid-submit').click()
    // Either the verified badge or an error appears.
    await Promise.race([
      page.getByTestId('bid-verified').waitFor({ timeout: 600_000 }),
      page.getByTestId('bid-error').waitFor({ timeout: 600_000 }),
    ])
    const error = (await page.getByTestId('bid-error').count()) ? await page.getByTestId('bid-error').innerText() : null
    const wall = Date.now() - t0
    if (error) return { error, wall, address: b.address }
    const txText = await page.locator('text=/tx 0x[0-9a-f]+/').first().innerText()
    const txHash = txText.match(/0x[0-9a-fA-F]{64}/)[0]
    const gas = await page.getByTestId('bid-gas').innerText()
    // `bid-timings` sits inside a collapsed <details>: innerText() is empty there, textContent() is not.
    const timings = JSON.parse(await page.getByTestId('bid-timings').textContent())
    return { txHash, gas: Number(gas), timings, wall, address: b.address }
  }

  // 3. Over-balance bid must FAIL locally (app-leg predicate) before any proof is generated.
  log(`bidder ${OVER_BALANCE.bidder} (${BIDDERS[OVER_BALANCE.bidder].address}, balance ${BIDDERS[OVER_BALANCE.bidder].balance}) attempts bid ${OVER_BALANCE.bid} — must fail at proving`)
  const over = await bidViaClient(OVER_BALANCE)
  if (!over.error || !/exceeds your attested balance/.test(over.error)) {
    throw new Error(`over-balance bid did NOT fail as expected: ${JSON.stringify(over)}`)
  }
  log(`  ✔ rejected client-side in ${over.wall} ms: "${over.error}"`)
  report.overBalance = over

  // 4. Four real bids through the client.
  for (const b of BIDS) {
    log(`bidder ${b.bidder} (${BIDDERS[b.bidder].address}) bids ${b.bid} via the client…`)
    const r = await bidViaClient(b)
    if (r.error) throw new Error(`bid by bidder ${b.bidder} failed: ${r.error}`)
    report.txs.push({ bidder: b.bidder, address: r.address, bid: b.bid, txHash: r.txHash, gas: r.gas, wall_ms: r.wall, timings: r.timings })
    log(`  ✔ tx ${r.txHash} gas ${r.gas} — encrypt ${Math.round(r.timings.encryptMs)} ms, prove app/ct1/ct0 ${Math.round(r.timings.proveMs.app)}/${Math.round(r.timings.proveMs.ct1)}/${Math.round(r.timings.proveMs.ct0)} ms, total ${r.wall} ms`)
  }
  const indexed = await waitFor('4 bids indexed', async () => {
    const r = await api(`/rounds/${e3Id}`)
    return r.bids.length >= 4 && r.bids.every((x) => x.ciphertextAvailable) ? r : null
  }, 60_000, 2000)
  log(`server indexed ${indexed.bids.length} bids, all ciphertexts recovered from calldata`)

  // 5. Replay: re-send bid #0's exact calldata from its own wallet → DuplicateSubmission.
  {
    const publicClient = createPublicClient({ transport: http(RPC) })
    const first = report.txs[0]
    const tx = await publicClient.getTransaction({ hash: first.txHash })
    const account = privateKeyToAccount(BIDDERS[first.bidder].key)
    const wallet = createWalletClient({ account, transport: http(RPC) })
    const abi = parseAbi(['function publishInput(uint256 e3Id, bytes data)', 'error DuplicateSubmission(uint256 e3Id, bytes32 uCommitment)'])
    let reverted = null
    try {
      await publicClient.call({ account, to: tx.to, data: tx.input, gas: 29_000_000n })
    } catch (e) {
      // viem nests the raw revert data several `cause` levels deep (ContractFunctionExecutionError
      // → CallExecutionError → RpcRequestError.data); walk the chain instead of guessing a depth.
      let data = null
      for (let c = e, d = 0; c && d < 8 && !data; c = c.cause, d++) {
        if (typeof c.data === 'string' && c.data.startsWith('0x')) data = c.data
      }
      data ??= (e.message.match(/custom error (0x[0-9a-f]{8}): ([0-9a-f]+)/i) ?? []).slice(1).join('')
      try {
        reverted = decodeErrorResult({ abi, data })
      } catch {
        reverted = { errorName: 'unknown', raw: String(e.shortMessage ?? e.message).slice(0, 200) }
      }
    }
    if (!reverted) throw new Error('replay of an accepted bid did NOT revert')
    // Also send it for real so the revert is on-chain evidence.
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
    if (reverted.errorName !== 'DuplicateSubmission') throw new Error(`replay reverted with ${reverted.errorName}, expected DuplicateSubmission`)
    void encodeAbiParameters
    void parseAbiParameters
  }

  // 6. Close the bidding window (anvil: jump chain time past inputWindow[1]) → the server's
  //    deadline hook evaluates + publishes (the "Evaluate now" button is the manual fallback) →
  //    threshold decryption → results.
  {
    const publicClient = createPublicClient({ transport: http(RPC) })
    // The ciphernodes' EVM gateway FAILS CLOSED when block time runs > 300 s ahead of their wall
    // clock (chain-drift guard) — one big `evm_increaseTime` jump silently kills the decryption
    // leg. Burn the excess window in real time first, then jump at most MAX_JUMP.
    const MAX_JUMP = 250
    let latest = await publicClient.getBlock()
    let remaining = Number(round.inputWindow[1]) - Number(latest.timestamp)
    if (remaining > MAX_JUMP) {
      log(`window has ${remaining}s left; waiting ${remaining - MAX_JUMP}s in real time (node drift guard is 300 s)`)
      await sleep((remaining - MAX_JUMP) * 1000)
      latest = await publicClient.getBlock()
    }
    const jump = Number(round.inputWindow[1]) - Number(latest.timestamp) + 5
    if (jump > 0) {
      await fetch(RPC, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'evm_increaseTime', params: [jump] }) })
      await fetch(RPC, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'evm_mine', params: [] }) })
      log(`bidding window closed (chain time +${jump}s)`)
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
  const res = finished.results
  const expectedWinner = BIDS.reduce((best, b, i) => (b.bid > BIDS[best].bid ? i : best), 0)
  log(`results: winner bidder #${res.winner} (${res.winnerAddress}); signs ${JSON.stringify(res.signs)}; values ${JSON.stringify(res.values)}`)
  if (res.winner !== expectedWinner) throw new Error(`wrong winner: ${res.winner}, expected ${expectedWinner} (bid ${BIDS[expectedWinner].bid})`)
  if (res.winnerAddress.toLowerCase() !== BIDDERS[BIDS[expectedWinner].bidder].address.toLowerCase()) throw new Error('winner address mismatch')
  for (const [p, [a, b]] of res.pairs.entries()) {
    const expect = BIDS[a].bid > BIDS[b].bid ? 1 : -1
    if (res.signs[p] !== expect) throw new Error(`pair (${a},${b}): sign ${res.signs[p]}, expected ${expect}`)
    if (Math.abs(Math.abs(res.values[p]) - 1) > 0.05) throw new Error(`pair (${a},${b}): slot ${res.values[p]} not a saturated ±1 (magnitude leak)`)
  }
  if (!res.binarized) throw new Error('server reports unsaturated slots')
  log('  ✔ correct winner; every opened slot is a saturated ±1 sign (2% gap pair included)')

  // Client page shows it too.
  await page.goto(`${CLIENT}/rounds/${e3Id}`, { waitUntil: 'load' })
  await page.getByTestId('winner').waitFor({ timeout: 30_000 })
  await page.getByTestId('binarized').waitFor({ timeout: 5_000 })
  await page.screenshot({ path: '/tmp/ckks-auction-results.png', fullPage: true })

  report.e3Id = e3Id
  report.results = res
  report.bids = BIDS.map((b) => ({ ...b, address: BIDDERS[b.bidder].address }))
  writeFileSync(REPORT, JSON.stringify(report, null, 2))
  log(`REPORT written to ${REPORT}`)
  await browser.close()
  console.log('\nCKKS AUCTION E2E PASSED')
}

main().catch((e) => {
  console.error('\nE2E FAILED:', e)
  writeFileSync(REPORT, JSON.stringify({ ...report, failed: String(e.message ?? e) }, null, 2))
  process.exit(1)
})
void readFileSync
