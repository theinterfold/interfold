// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { defineConfig, globalIgnores } from 'eslint/config'
import config from '@interfold/config/eslint.config.js'

export default defineConfig([
  globalIgnores([
    // Github submodules.
    'packages/crisp-contracts/lib/risc0-ethereum',
    // Build and cache directories.
    '**/node_modules/**',
    '**/dist/**',
    '**/build/**',
    '**/cache/**',
    '**/artifacts/**',
    '**/types/**',
    '**/.cache-synpress/**',
    '**/playwright-report/**',
    'packages/crisp-zk-inputs/pkg/**',
  ]),
  {
    extends: [config],
    files: ['**/*.{ts,tsx,js,jsx}'],
  },
])
