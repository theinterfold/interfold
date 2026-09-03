// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import topLevelAwait from 'vite-plugin-top-level-await'
import path from 'path'

// Same shape as examples/CRISP/client: bb.js + noir_js excluded from
// pre-bundling (worker URLs), COOP/COEP so the multithreaded WASM prover
// gets SharedArrayBuffer, ESM workers.
export default defineConfig({
  base: '/',
  define: { global: 'globalThis' },
  optimizeDeps: {
    esbuildOptions: { target: 'esnext' },
    exclude: ['@noir-lang/noirc_abi', '@noir-lang/acvm_js', '@noir-lang/noir_js', '@aztec/bb.js', '@interfold/ckks-zk-inputs'],
  },
  resolve: {
    alias: { '@': path.resolve(__dirname, './src') },
  },
  worker: { format: 'es' },
  plugins: [topLevelAwait(), react()],
  build: { target: 'esnext' },
  server: {
    port: 5174,
    fs: { allow: [path.resolve(__dirname, '../../..')] },
    headers: {
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Embedder-Policy': 'require-corp',
    },
  },
  preview: {
    port: 5174,
    headers: {
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Embedder-Policy': 'require-corp',
    },
  },
})
