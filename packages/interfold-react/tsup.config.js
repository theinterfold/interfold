// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { defineConfig } from 'tsup'
import { baseConfig } from '@interfold/config/tsup'

export default defineConfig({
  ...baseConfig,
  include: ['./src/**/*.ts'],
})
