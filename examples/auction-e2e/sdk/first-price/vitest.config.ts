// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  resolve: {
    // The decoders call `@interfold/sdk`, which the tests mock. Read core from the source so that the mock applies.
    alias: { '@interfold/auction-core': fileURLToPath(new URL('../core/src/index.ts', import.meta.url)) },
  },
  test: { include: ['src/**/*.test.ts'] },
})
