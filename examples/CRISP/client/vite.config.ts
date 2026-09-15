// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import viteTsconfigPaths from 'vite-tsconfig-paths'
import svgr from '@svgr/rollup'
import topLevelAwait from 'vite-plugin-top-level-await'
import path from 'path'
import { nodePolyfills } from 'vite-plugin-node-polyfills'

if (process.env.NO_HOT) {
  console.log('Running without HMR')
}
// const development: boolean = !process.env.NODE_ENV || process.env.NODE_ENV === 'development'
export default defineConfig({
  base: '/',
  define: {
    // here is the main update
    global: 'globalThis',
  },
  optimizeDeps: {
    esbuildOptions: { target: 'esnext' },
    // The SDK stays unbundled so its worker URLs remain package-relative. Its
    // CommonJS Poseidon dependency still needs Vite's ESM interop layer.
    include: ['@crisp-e3/sdk > poseidon-lite'],
    exclude: [
      '@rollup/browser',
      '@noir-lang/noirc_abi',
      '@noir-lang/acvm_js',
      '@noir-lang/noir_js',
      '@aztec/bb.js', // Pre-bundling breaks worker URLs (thread.worker.js, main.worker.js)
      // The SDK worker URL must stay relative to the installed SDK package.
      '@crisp-e3/sdk',
      '@crisp-e3/sdk/insecure',
      '@crisp-e3/sdk/secure-8192',
      '@crisp-e3/sdk/secure-16384',
    ],
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
      libs: path.resolve(__dirname, './libs'),
      'vite-plugin-node-polyfills/shims/buffer': path.resolve(__dirname, './node_modules/vite-plugin-node-polyfills/shims/buffer'),
    },
  },
  worker: {
    format: 'es',
  },
  plugins: [
    // here is the main update
    topLevelAwait(),
    react({
      jsxImportSource: '@emotion/react',
      babel: {
        plugins: ['@emotion/babel-plugin'],
      },
    }),
    viteTsconfigPaths(),
    svgr(),
    nodePolyfills({ include: ['buffer'] }),
  ],
  server: {
    open: true,
    // this sets a default port to 3000
    port: 3000,
    hmr: !process.env.NO_HOT,
    headers: {
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Embedder-Policy': 'require-corp',
    },
  },
})
