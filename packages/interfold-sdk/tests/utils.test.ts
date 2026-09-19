// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { describe, expect, it } from 'vitest'
import { DEFAULT_COMPUTE_PROVIDER_PARAMS } from '../src/utils'

describe('default compute provider', () => {
  it('selects OpenVM', () => {
    expect(DEFAULT_COMPUTE_PROVIDER_PARAMS.name).toBe('openvm')
  })
})
