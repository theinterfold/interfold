// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

// The simulation stays in ../ts and is imported as it is. Vite must be allowed to read it.
export default defineConfig({
  base: './',
  resolve: {
    alias: {
      '@designs': path.resolve(__dirname, '../ts/src/index.ts'),
    },
  },
  server: {
    fs: { allow: ['..'] },
  },
  plugins: [react()],
})
