// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { describe, expect, it } from 'vitest'

import { firstInRandomOrder } from '../../../client/src/utils/onchainCensus'

/// A random mask takes the first maskable registrant in a random order. Unmaskable registrants,
/// such as Safes above the ballot caps, must not make the search fail while one registrant is
/// maskable.
describe('client firstInRandomOrder', () => {
  it('visits each index once, so it finds the one accepted index among 100', async () => {
    const deadline = Date.now() + 60_000
    const visited: bigint[] = []
    const none = await firstInRandomOrder(
      100n,
      async (index) => {
        visited.push(index)
        return undefined
      },
      deadline,
    )

    expect(none).toBeUndefined()
    expect(visited.map(Number).sort((a, b) => a - b)).toEqual(Array.from({ length: 100 }, (_, i) => i))

    const found = await firstInRandomOrder(100n, async (index) => (index === 42n ? 'maskable' : undefined), deadline)
    expect(found).toBe('maskable')
  })
})
