// SPDX-License-Identifier: LGPL-3.0-only
// Browser probe: can Chrome prove the 38-limb ps2 Greco legs? Serves the ckks-common package + vendor bundle.
import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
const here = path.dirname(fileURLToPath(import.meta.url))
const interfold = path.resolve(here, '../../../..')
const pkg = path.join(interfold, 'examples/ckks-common/packages/ckks-zk-inputs')
const circuits = path.join(interfold, 'circuits/bin/threshold/target')
const mime = { '.html': 'text/html', '.js': 'text/javascript', '.mjs': 'text/javascript', '.json': 'application/json', '.wasm': 'application/wasm', '.bin': 'application/octet-stream' }
const server = createServer(async (req, res) => {
  try {
    const u = decodeURIComponent(req.url.split('?')[0])
    let f
    if (u === '/') f = path.join(here, 'probe.html')
    else if (u === '/vendor/noir_js') f = path.join(pkg, 'dist/vendor/noir_js.js')
    else if (u === '/vendor/bb.js') f = path.join(pkg, 'dist/vendor/bb.js')
    else if (u.startsWith('/vendor/')) f = path.join(pkg, 'dist/vendor', u.slice(8))
    else if (u.startsWith('/circuits/')) f = path.join(circuits, u.slice(10))
    else if (u.startsWith('/pkg/')) f = path.join(pkg, u.slice(5))
    else { res.writeHead(404); res.end(); return }
    const body = await readFile(f)
    res.writeHead(200, { 'Content-Type': mime[path.extname(f)] ?? 'application/octet-stream', 'Cross-Origin-Opener-Policy': 'same-origin', 'Cross-Origin-Embedder-Policy': 'require-corp' })
    res.end(body)
  } catch { res.writeHead(404); res.end() }
})
server.listen(0, '127.0.0.1', async () => {
  const port = server.address().port
  const { chromium } = await import(path.join(pkg, 'node_modules/playwright/index.mjs'))
  const browser = await chromium.launch({ headless: true, executablePath: process.env.CHROME_BIN })
  const page = await browser.newPage()
  page.on('console', (m) => { if (m.type() === 'error') console.error('console error:', m.text()) })
  page.on('pageerror', (e) => console.error('pageerror', e))
  const srs = process.argv[2] ?? '20'
  await page.goto(`http://127.0.0.1:${port}/?srs=${srs}`)
  try {
    await page.waitForFunction(() => window.__done !== undefined, null, { timeout: 900_000 })
    console.log('RESULT', await page.evaluate(() => window.__done))
    console.log(JSON.stringify(await page.evaluate(() => window.__t), null, 1))
  } catch (e) { console.error('TIMEOUT/ERR', e.message); console.log(JSON.stringify(await page.evaluate(() => window.__t).catch(() => ({})))) }
  await browser.close(); server.close()
})
