// SPDX-License-Identifier: LGPL-3.0-only

import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['tests/integration/*.test.ts'],
    // Real recursive proofs share one worker to bound memory and setup cost.
    poolOptions: { forks: { singleFork: true } },
    pool: 'forks',
    hookTimeout: 600_000,
    testTimeout: 120_000,
  },
})
