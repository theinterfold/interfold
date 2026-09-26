// SPDX-License-Identifier: LGPL-3.0-only

import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['tests/*.test.ts'],
  },
})
