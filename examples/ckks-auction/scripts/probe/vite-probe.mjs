// SPDX-License-Identifier: LGPL-3.0-only
//
// Vite-bundle + browser-proving probe: drives the client's /probe page (no chain, no server).
//   node scripts/probe/vite-probe.mjs http://127.0.0.1:5173
import { chromium } from 'playwright'

const CLIENT = process.argv[2] ?? 'http://127.0.0.1:5173'
const browser = await chromium.launch({ headless: true, executablePath: process.env.CHROME_BIN || undefined })
const page = await browser.newPage()
page.on('console', (m) => {
  if (m.type() === 'error') console.log('  [browser]', m.text().slice(0, 400))
})
page.on('pageerror', (e) => console.error('  [pageerror]', e.message))
await page.goto(`${CLIENT}/probe`, { waitUntil: 'load' })
for (const which of ['probe-over', 'probe-ok']) {
  const t0 = Date.now()
  await page.getByTestId(which).click()
  await Promise.race([
    page.getByTestId('probe-result').waitFor({ timeout: 600_000 }),
    page.getByTestId('probe-error').waitFor({ timeout: 600_000 }),
  ])
  const err = (await page.getByTestId('probe-error').count()) ? await page.getByTestId('probe-error').innerText() : null
  console.log(which, 'wall', Date.now() - t0, 'ms', err ? 'ERROR: ' + err : '')
  if (!err) console.log(await page.getByTestId('probe-result').innerText())
  console.log(await page.getByTestId('probe-log').innerText())
}
await browser.close()
