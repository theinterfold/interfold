// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { defineConfig } from 'tsup'
import { baseConfig } from '@interfold/config/tsup'

export default defineConfig({
  ...baseConfig,
  entry: ['src/index.ts', 'src/prover.ts'],
  // The root and `prover` share modules: one chunk keeps one copy of each enum.
  splitting: true,
  // A private workspace package that the SDK bundles in. The circuits are inlined from `circuits/`
  // (see `scripts/copy-circuits.mjs`).
  noExternal: ['@interfold/user-data-encryption-prover'],

  format: ['esm'],
  outExtension: () => ({ js: '.js' }),
})
