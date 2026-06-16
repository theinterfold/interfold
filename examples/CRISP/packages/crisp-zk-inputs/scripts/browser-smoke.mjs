// SPDX-License-Identifier: LGPL-3.0-only
//
// Browser smoke test: load crisp-zk-inputs WASM in headless Chrome and encrypt once.

import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium } from 'playwright'

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..')

const mime = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
}

function startServer() {
  return new Promise((resolve) => {
    const server = createServer(async (req, res) => {
      try {
        const urlPath = req.url?.split('?')[0] ?? '/'
        const rel = urlPath === '/' ? '/smoke.html' : urlPath
        const filePath = path.join(root, rel)
        if (!filePath.startsWith(root)) {
          res.writeHead(403)
          res.end()
          return
        }
        const body = await readFile(filePath)
        const ext = path.extname(filePath)
        res.writeHead(200, { 'Content-Type': mime[ext] ?? 'application/octet-stream' })
        res.end(body)
      } catch {
        res.writeHead(404)
        res.end()
      }
    })
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address()
      resolve({ server, port })
    })
  })
}

async function main() {
  const { server, port } = await startServer()
  const launchOptions = { headless: true }
  if (process.env.CHROME_BIN) {
    launchOptions.executablePath = process.env.CHROME_BIN
  }

  try {
    const browser = await chromium.launch(launchOptions)
    const page = await browser.newPage()
    page.on('pageerror', (err) => console.error('page error:', err))

    await page.goto(`http://127.0.0.1:${port}/smoke.html`, { waitUntil: 'networkidle' })
    await page.waitForFunction(() => window.__wasmSmoke !== undefined, null, { timeout: 180_000 })

    const result = await page.evaluate(() => window.__wasmSmoke)
    if (result !== 'ok') {
      throw new Error(`WASM smoke failed: ${result}`)
    }
    console.log('crisp-zk-inputs browser smoke: ok (generateKeys + encryptVote)')
    await browser.close()
  } finally {
    server.close()
  }
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
