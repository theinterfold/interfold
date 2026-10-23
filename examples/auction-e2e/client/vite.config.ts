// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import viteTsconfigPaths from 'vite-tsconfig-paths'
import wasm from 'vite-plugin-wasm'
import topLevelAwait from 'vite-plugin-top-level-await'
import path from 'path'

// bb.js runs its proving threads as SharedArrayBuffer workers, which the browser only allows on a
// cross-origin isolated page.
const crossOriginIsolation = {
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Embedder-Policy': 'require-corp',
}

export default defineConfig({
  base: '/',
  define: {
    global: 'globalThis',
  },
  optimizeDeps: {
    esbuildOptions: { target: 'esnext' },
    exclude: [
      '@rollup/browser',
      '@noir-lang/noirc_abi',
      '@noir-lang/acvm_js',
      '@noir-lang/noir_js',
      '@aztec/bb.js', // Pre-bundling breaks worker URLs (thread.worker.js, main.worker.js)
    ],
  },
  build: {
    target: 'esnext',
    commonjsOptions: {
      include: [/node_modules/, /packages\/evm/],
    },
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
      '@shared': path.resolve(__dirname, '../shared'),
      '@contract-types': path.resolve(__dirname, '../types'),
    },
  },
  worker: {
    format: 'es',
  },
  plugins: [wasm(), topLevelAwait(), react(), viteTsconfigPaths()],
  server: {
    open: true,
    port: 3000,
    headers: crossOriginIsolation,
  },
  preview: {
    open: true,
    port: 3000,
    headers: crossOriginIsolation,
  },
})
