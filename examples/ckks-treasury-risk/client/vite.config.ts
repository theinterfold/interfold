// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { defineConfig } from 'vite'
import type { Plugin } from 'vite'
import react from '@vitejs/plugin-react'
import fs from 'fs'
import path from 'path'

// COOP/COEP: bb.js needs cross-origin isolation for its multithreaded (SharedArrayBuffer) worker
// backend — without it the Greco legs prove single-threaded.
const isolationHeaders = {
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Embedder-Policy': 'require-corp',
}

const CIRCUITS_DIR = process.env.CKKS_CIRCUITS_DIR ?? path.resolve(__dirname, '../../../circuits/bin/threshold/target')

/** Serves the compiled Noir circuits (`circuits/bin/threshold/target/<name>.json`) at `/circuits/<name>.json`. */
const serveCircuits = (): Plugin => ({
  name: 'serve-circuits',
  configureServer(server) {
    server.middlewares.use((req, res, next) => {
      const m = req.url?.match(/^\/circuits\/([a-z0-9_]+\.json)$/)
      if (!m) return next()
      const file = path.join(CIRCUITS_DIR, m[1])
      if (!fs.existsSync(file)) {
        res.statusCode = 404
        return res.end(`circuit not found: ${file}`)
      }
      res.setHeader('content-type', 'application/json')
      fs.createReadStream(file).pipe(res)
    })
  },
})

export default defineConfig({
  define: { global: 'globalThis' },
  optimizeDeps: {
    esbuildOptions: { target: 'esnext' },
    // Pre-bundling breaks bb.js worker URLs (main.worker.js / thread.worker.js) and noir wasm.
    exclude: ['@noir-lang/noirc_abi', '@noir-lang/acvm_js', '@noir-lang/noir_js', '@aztec/bb.js', '@interfold/ckks-zk-inputs'],
  },
  resolve: { alias: { '@': path.resolve(__dirname, './src') } },
  worker: { format: 'es' },
  plugins: [react(), serveCircuits()],
  server: {
    port: 5177,
    headers: isolationHeaders,
    fs: { allow: [path.resolve(__dirname, '../../..')] },
  },
  preview: { headers: isolationHeaders },
})
