// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Browser smoke: serve smoke.html + the built package + a browser bundle
// of noir_js / bb.js (esbuild) + the ps3 circuit JSON, run headless
// Chromium, wait for the page to finish, print timings.
//
//   node scripts/browser-smoke.mjs [--skip-prove] [--headed]
//
// Serves cross-origin-isolation headers (COOP/COEP) so bb.js can use its
// multi-threaded SharedArrayBuffer worker backend — the same requirement a
// production app has (see CRISP client's vite config).

import { createServer } from 'node:http'
import { readFile, mkdir, writeFile } from 'node:fs/promises'
import { existsSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..')
const interfold = path.join(root, '../../../..')
const circuits = path.join(interfold, 'circuits/bin/threshold/target')
const args = process.argv.slice(2)

const mime = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.json': 'application/json',
  '.wasm': 'application/wasm',
  '.bin': 'application/octet-stream',
}

async function bundleVendor() {
  // esbuild lives in the interfold root node_modules; resolve from there.
  let esbuild
  try {
    esbuild = require(path.join(interfold, 'node_modules/esbuild'))
  } catch {
    esbuild = require('esbuild')
  }
  const out = path.join(root, 'dist/vendor')
  await mkdir(out, { recursive: true })
  await writeFile(
    path.join(out, 'noir_js.entry.js'),
    `export * from '@noir-lang/noir_js'\n`,
  )
  await writeFile(path.join(out, 'bb.entry.js'), `export * from '@aztec/bb.js'\n`)
  const { realpath } = await import('node:fs/promises')
  const bbBrowser = (await realpath(path.join(root, 'node_modules/@aztec/bb.js'))) + '/dest/browser'
  const entries = [
    ['noir_js.entry.js', 'noir_js.js'],
    ['bb.entry.js', 'bb.js'],
    // bb.js spawns its workers via `new URL('./main.worker.js', import.meta.url)`;
    // bundle them next to bb.js so the relative URL resolves under /vendor/.
    [`${bbBrowser}/barretenberg_wasm/barretenberg_wasm_main/factory/browser/main.worker.js`, 'main.worker.js'],
    [`${bbBrowser}/barretenberg_wasm/barretenberg_wasm_thread/factory/browser/thread.worker.js`, 'thread.worker.js'],
  ]
  for (const [entry, name] of entries) {
    await esbuild.build({
      entryPoints: [entry.startsWith('/') ? entry : path.join(out, entry)],
      bundle: true,
      format: 'esm',
      platform: 'browser',
      target: 'es2022',
      outfile: path.join(out, name),
      logLevel: 'error',
      nodePaths: [path.join(root, 'node_modules')],
      define: { 'process.env.NODE_ENV': '"production"' },
    })
  }
  // noir_js (acvm_js / noirc_abi) fetches its wasm via `new URL('x_bg.wasm', import.meta.url)`.
  const { copyFile } = await import('node:fs/promises')
  const noirDir = await realpath(path.join(root, 'node_modules/@noir-lang/noir_js'))
  for (const [pkgName, file] of [
    ['@noir-lang/acvm_js', 'acvm_js_bg.wasm'],
    ['@noir-lang/noirc_abi', 'noirc_abi_wasm_bg.wasm'],
  ]) {
    // pnpm layout: siblings of noir_js under its own node_modules or the .pnpm store.
    const candidates = [
      path.join(noirDir, 'node_modules', pkgName),
      path.join(noirDir, '../..', pkgName),
    ]
    let dir
    for (const c of candidates) {
      try {
        dir = await realpath(c)
        break
      } catch {}
    }
    if (!dir) throw new Error(`cannot locate ${pkgName} next to noir_js`)
    await copyFile(path.join(dir, 'web', file), path.join(out, file))
  }
  console.log('bundled dist/vendor/{noir_js,bb,main.worker,thread.worker}.js + noir wasms')
}

function startServer() {
  return new Promise((resolve) => {
    const server = createServer(async (req, res) => {
      try {
        const urlPath = decodeURIComponent(req.url?.split('?')[0] ?? '/')
        if (urlPath === '/favicon.ico') { res.writeHead(204); res.end(); return }
        let filePath
        if (urlPath === '/') filePath = path.join(root, 'smoke.html')
        else if (urlPath === '/vendor/noir_js') filePath = path.join(root, 'dist/vendor/noir_js.js')
        else if (urlPath === '/vendor/bb.js') filePath = path.join(root, 'dist/vendor/bb.js')
        else if (urlPath.startsWith('/vendor/')) filePath = path.join(root, 'dist/vendor', urlPath.slice('/vendor/'.length))
        else if (urlPath.startsWith('/circuits/')) filePath = path.join(circuits, urlPath.slice('/circuits/'.length))
        else filePath = path.join(root, urlPath)
        if (!filePath.startsWith(root) && !filePath.startsWith(circuits)) {
          res.writeHead(403)
          res.end()
          return
        }
        const body = await readFile(filePath)
        const ext = path.extname(filePath)
        res.writeHead(200, {
          'Content-Type': mime[ext] ?? 'application/octet-stream',
          'Cross-Origin-Opener-Policy': 'same-origin',
          'Cross-Origin-Embedder-Policy': 'require-corp',
        })
        res.end(body)
      } catch {
        res.writeHead(404)
        res.end()
      }
    })
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }))
  })
}

async function main() {
  if (!existsSync(path.join(root, 'dist/web/index.js'))) throw new Error('run `pnpm build` first')
  await bundleVendor()
  const { server, port } = await startServer()
  const { chromium } = await import('playwright')
  const launchOptions = { headless: !args.includes('--headed') }
  if (process.env.CHROME_BIN) launchOptions.executablePath = process.env.CHROME_BIN
  try {
    const browser = await chromium.launch(launchOptions)
    const page = await browser.newPage()
    page.on('pageerror', (err) => console.error('page error:', err))
    page.on('console', (m) => {
      if (m.text().includes('crossOriginIsolated')) console.log('  ' + m.text())
      if (m.type() === 'error') console.error('console error:', m.text())
    })
    const q = args.includes('--skip-prove') ? '?skip-prove' : ''
    await page.goto(`http://127.0.0.1:${port}/smoke.html${q}`, { waitUntil: 'load' })
    await page.waitForFunction(() => window.__wasmSmoke !== undefined, null, { timeout: 600_000 })
    const result = await page.evaluate(() => window.__wasmSmoke)
    const timings = await page.evaluate(() => window.__smokeTimings)
    console.log('BROWSER TIMINGS (ms)')
    for (const [k, v] of Object.entries(timings)) console.log(`  ${k.padEnd(36)} ${v}`)
    if (result !== 'ok') throw new Error(`browser smoke failed: ${result}`)
    console.log('ckks-zk-inputs browser smoke: ok')
    await browser.close()
  } finally {
    server.close()
  }
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
