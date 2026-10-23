// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { describe, expect, it } from 'vitest'

import { blockRanges, getLogsChunked } from './logs'

describe('blockRanges', () => {
  it('covers the range once, in chunks of at most the size', () => {
    expect(blockRanges(10n, 25n, 10n)).toEqual([
      { fromBlock: 10n, toBlock: 19n },
      { fromBlock: 20n, toBlock: 25n },
    ])
  })

  it('returns one range for a single block, and none for an empty span', () => {
    expect(blockRanges(5n, 5n, 100n)).toEqual([{ fromBlock: 5n, toBlock: 5n }])
    expect(blockRanges(6n, 5n, 100n)).toEqual([])
  })

  it('rejects a chunk size that is not positive', () => {
    expect(() => blockRanges(0n, 5n, 0n)).toThrow()
  })
})

describe('getLogsChunked', () => {
  it('queries each chunk in order and joins the results', async () => {
    const requested: Array<[bigint, bigint]> = []
    const logs = await getLogsChunked(
      async ({ fromBlock, toBlock }) => {
        requested.push([fromBlock, toBlock])
        return [fromBlock]
      },
      0n,
      4n,
      2n,
    )
    expect(requested).toEqual([
      [0n, 1n],
      [2n, 3n],
      [4n, 4n],
    ])
    expect(logs).toEqual([0n, 2n, 4n])
  })
})
