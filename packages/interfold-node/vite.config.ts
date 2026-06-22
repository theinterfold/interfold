// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import path from 'node:path'
import { fileURLToPath } from 'node:url'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

const here = path.dirname(fileURLToPath(import.meta.url))

export default defineConfig({
  base: '/assets/',
  plugins: [react()],
  publicDir: path.resolve(here, '../interfold-dashboard/src/assets'),
  build: {
    outDir: path.resolve(here, '../../crates/dashboard/assets'),
    emptyOutDir: true,
    rollupOptions: {
      output: {
        entryFileNames: 'app.js',
        chunkFileNames: '[name].js',
        assetFileNames: (asset) => (asset.name?.endsWith('.css') ? 'app.css' : '[name][extname]'),
      },
    },
  },
  server: {
    port: 5174,
    proxy: {
      '/api': 'http://127.0.0.1:9092',
    },
  },
})
