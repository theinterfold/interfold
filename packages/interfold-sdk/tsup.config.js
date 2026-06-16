// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { defineConfig } from 'tsup'
import { baseConfig } from '@interfold/config/tsup'

const entry = ['src/index.ts', 'src/crypto/index.ts', 'src/contracts/index.ts', 'src/events/index.ts']

export default defineConfig([
  {
    ...baseConfig,
    entry,
    include: ['./src/**/*.ts'],
    format: ['esm'],
    outExtension: () => ({
      js: '.js',
    }),
    esbuildOptions: (options) => {
      options.alias = {
        '@interfold/wasm/init': '../../crates/wasm/init_node.js',
      }
    },
  },
  {
    ...baseConfig,
    entry,
    include: ['./src/**/*.ts'],
    format: ['cjs'],
    // Avoid running DTS build twice for the same entries.
    dts: false,
    outExtension: () => ({
      js: '.cjs',
    }),
    esbuildOptions: (options) => {
      options.alias = {
        '@interfold/wasm/init': '../../crates/wasm/init_node.cjs',
      }
    },
  },
])
