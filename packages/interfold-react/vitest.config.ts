// SPDX-License-Identifier: LGPL-3.0-only
import { defineConfig } from 'vitest/config'
import { fileURLToPath } from 'node:url'

export default defineConfig({
  resolve: {
    alias: { '@interfold/sdk': fileURLToPath(new URL('../interfold-sdk/src/index.ts', import.meta.url)) },
  },
  test: { include: ['tests/**/*.test.ts'] },
})
