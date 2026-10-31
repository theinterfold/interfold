// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import assert from 'node:assert/strict'
import test from 'node:test'
import { invalidBlockOverrides } from './networks'

test('block overrides must be whole numbers on every network', () => {
  assert.deepEqual(
    invalidBlockOverrides({
      VITE_MAINNET_DEPLOY_BLOCK: '26300000',
      VITE_MAINNET_IDENTITY_DEPLOY_BLOCK: '26300000.0',
      VITE_SEPOLIA_DEPLOY_BLOCK: ' ',
      VITE_SEPOLIA_IDENTITY_DEPLOY_BLOCK: '-1',
    }),
    ['VITE_SEPOLIA_IDENTITY_DEPLOY_BLOCK', 'VITE_MAINNET_IDENTITY_DEPLOY_BLOCK'],
  )
  assert.deepEqual(invalidBlockOverrides({}), [])
})
